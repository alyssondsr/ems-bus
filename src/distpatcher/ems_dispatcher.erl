%%********************************************************************
%% @title Module ems_dispatcher
%% @version 1.0.0
%% @doc Responsible for forwarding the requests to services.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_dispatcher).

-include("../include/ems_config.hrl").
-include("../include/ems_schema.hrl").

%% Client API
-export([start/0, dispatch_request/2]).


start() -> 
	ems_cache:new(ets_result_cache_get),
	ets:new(ctrl_node_dispatch, [set, named_table, public]).


check_result_cache(ReqHash, Timestamp2) ->
	case ets:lookup(ets_result_cache_get, ReqHash) of
		[] -> false; 
		[{_, {Timestamp, _, ResultCache}}] when Timestamp2 - Timestamp > ResultCache ->	false;
		[{_, {_, Request, _}}] -> {true, Request}
	end.

dispatch_request(Request = #request{req_hash = ReqHash, 
								    ip = Ip,
								    content_type = ContentTypeReq,
								    type = Type,
								    t1 = T1,
									params_url = ParamsMap,
									querystring_map = QuerystringMap},
				 Service = #service{content_type = ContentTypeService,
									tcp_allowed_address_t = AllowedAddress,
									result_cache = ResultCache,
									service_exec_metric_name = ServiceExecMetricName,
									service_result_cache_hit_metric_name = ServiceResultCacheHitMetricName,
									service_host_denied_metric_name = ServiceHostDeniedMetricName,
									service_auth_denied_metric_name = ServiceAuthDeniedMetricName}) -> 
	?DEBUG("ems_dispatcher lookup request ~p.", [Request]),
	ems_db:inc_counter(ServiceExecMetricName),								
	case ems_util:allow_ip_address(Ip, AllowedAddress) of
		true ->
			case ems_auth_user:authenticate(Service, Request) of
				{ok, Client, User, AccessToken, Scope} -> 
					Request2 = Request#request{service = Service,
												params_url = ParamsMap,
												querystring_map = QuerystringMap,
												client = Client,
												user = User,
												scope = Scope,
												access_token = AccessToken,
												content_type = 	case ContentTypeService of
																	  undefined -> ContentTypeReq;
																	  _ -> ContentTypeService
																end},
					case Type of
						<<"OPTIONS">> -> 
								{ok, request, Request2#request{code = 200, 
															   content_type = ?CONTENT_TYPE_JSON,
															   response_data = ems_catalog:get_metadata_json(Service),
															   response_header = #{<<"ems-node">> => ems_util:node_binary()},
															   latency = ems_util:get_milliseconds() - T1}
								};
						"HEAD" -> 
								{ok, request, Request2#request{code = 200, 
															   response_header = #{<<"ems-node">> => ems_util:node_binary()},
															   latency = ems_util:get_milliseconds() - T1}
								};
						<<"GET">> ->
							case ResultCache > 0 of
								true ->
									case check_result_cache(ReqHash, T1) of
										{true, RequestCache} -> 
											ems_db:inc_counter(ServiceResultCacheHitMetricName),								
											{ok, request, Request2#request{result_cache = true,
																		   code = RequestCache#request.code,
																		   reason = RequestCache#request.reason,
																		   content_type = RequestCache#request.content_type,
																		   response_data = RequestCache#request.response_data,
																		   response_header = RequestCache#request.response_header,
																		   result_cache_rid = RequestCache#request.rid,
																		   etag = RequestCache#request.etag,
																		   filename = RequestCache#request.filename,
																		   latency = ems_util:get_milliseconds() - T1}};
										false -> dispatch_service_work(Request2, Service)
									end;
								false -> dispatch_service_work(Request2, Service)
							end;
						_ ->
							dispatch_service_work(Request2, Service)
					end;
				{error, Reason} = Error -> 
					Request2 = Request#request{service = Service,
											   params_url = ParamsMap,
											   querystring_map = QuerystringMap},
					case Type of
						<<"OPTIONS">> -> 
								{ok, request, Request2#request{code = 200, 
															   content_type = ?CONTENT_TYPE_JSON,
															   response_data = ems_catalog:get_metadata_json(Service),
															   response_header = #{<<"ems-node">> => ems_util:node_binary()},
															   latency = ems_util:get_milliseconds() - T1}
								};
						"HEAD" -> 
								{ok, request, Request2#request{code = 200, 
															   response_header = #{<<"ems-node">> => ems_util:node_binary()},
															   latency = ems_util:get_milliseconds() - T1}
								};
						 _ -> 
							ems_db:inc_counter(ServiceAuthDeniedMetricName),								
							{error, request, Request2#request{code = 400, 
															  content_type = ?CONTENT_TYPE_JSON,
															  reason = Reason, 
															  response_data = ems_schema:to_json(Error), 
															  response_header = #{<<"ems-node">> => ems_util:node_binary()},
															  latency = ems_util:get_milliseconds() - T1}
							}
					end
			end;
		false -> 
			ems_db:inc_counter(ServiceHostDeniedMetricName),								
			{error, host_denied}
	end.
	


dispatch_service_work(Request,
					 _Service = #service{name = ServiceName,
										 owner = ServiceOwner,
										 host = '',
										 module_name = ModuleName,
										 module = Module,
										 function = Function}) ->
	ems_logger:info("ems_dispatcher send local msg to ~s.", [ModuleName]),
	{Reason, Request3 = #request{response_header = ResponseHeader}} = apply(Module, Function, [Request]),
	Request4 = Request3#request{reason = case Request3#request.reason of
												undefined -> Reason;
												Reason2 -> Reason2
										 end,
								response_header = ResponseHeader#{<<"ems-node">> => ems_util:node_binary(),
																  <<"ems-catalog">> => ServiceName,
																  <<"ems-owner">> => ServiceOwner}},
	dispatch_middleware_function(Request4);
dispatch_service_work(Request = #request{rid = Rid,
										  type = Type,
										  url = Url,
										  payload = Payload,
										  t1 = T1,
										  client = Client,
										  user = User,
										  scope = Scope,
										  content_type = ContentType,  
										  params_url = ParamsMap,
										  querystring_map = QuerystringMap},
					  Service = #service{name = ServiceName,
										 owner = ServiceOwner,
										 host = Host,
										 host_name = HostName,
										 module_name = ModuleName,
										 module = Module,
										 function_name = FunctionName, 
										 timeout = Timeout,
										 service_timeout_metric_name = ServiceTimeoutMetricName,
										 service_unavailable_metric_name = ServiceUnavailableMetricName}) ->
	case get_work_node(Host, Host, HostName, ModuleName, 1) of
		{ok, Node} ->
			case erlang:is_tuple(Client) of
				false -> 
					ClientJson = <<"{id:0, codigo:0, name:\"public\", active:true}">>;
				_ -> 
					ClientJson = ems_client:to_json(Client)
			end,
			case erlang:is_tuple(User) of
				false -> 
					UserJson = <<"{id:0, codigo:0, name:\"public\", login:null, email:null, type:null, subtype:null, cpf:null, active:true, lista_perfil:{}, lista_permission:{}}">>;
				_ -> 
					case erlang:is_tuple(Client) of
						true -> UserJson = ems_user:to_resource_owner(User, Client#client.id);
						false -> UserJson = ems_user:to_resource_owner(User)
					end
			end,
			Msg = {{Rid, Url, binary_to_list(Type), ParamsMap, QuerystringMap, Payload, ContentType, ModuleName, FunctionName, 
					ClientJson, UserJson, ems_catalog:get_metadata_json(Service), Scope, 
					undefined, undefined}, self()
				  },
			{Module, Node} ! Msg,
			NodeBin = erlang:atom_to_binary(Node, utf8),
			ems_logger:info("ems_dispatcher send msg to ~p with timeout ~pms.", [{Module, Node}, Timeout]),
			receive 
				{Code, RidRemote, {Reason, ResponseDataReceived}} when RidRemote == Rid  -> 
					case Reason == ok andalso byte_size(ResponseDataReceived) >= 27 of
						true ->
							case ResponseDataReceived of
								% Os dados recebidos do Java pode ser um array de bytes que possui um "header especial" que precisa ser removido do verdadeiro conteúdo
								<<HeaderJavaSerializable:25/binary, _H2:2/binary, DataBin/binary>> -> 
									case HeaderJavaSerializable =:= <<172,237,0,5,117,114,0,2,91,66,172,243,23,248,6,8,84,224,2,0,0,120,112,0,0>> of
										true -> ResponseData = DataBin;
										false -> ResponseData = ResponseDataReceived
									end;
								_ -> ResponseData = ResponseDataReceived
							end;
						false -> ResponseData = ResponseDataReceived
					end,
					Request2 = Request#request{code = Code,
											   reason = Reason,
											   service = Service,
											   params_url = ParamsMap,
											   querystring_map = QuerystringMap,
											   response_header = #{<<"ems-node">> => NodeBin,
																   <<"ems-catalog">> => ServiceName,
																   <<"ems-owner">> => ServiceOwner},
											   response_data = ResponseData},
					dispatch_middleware_function(Request2);
				Msg -> 
					ems_logger:error("ems_dispatcher received invalid message ~p.", [Msg]), 
					{error, request, Request#request{code = 500,
													 reason = einvalid_rec_message,
													 content_type = ?CONTENT_TYPE_JSON,
													 service = Service,
													 params_url = ParamsMap,
													 querystring_map = QuerystringMap,
													 response_header = #{<<"ems-node">> => NodeBin,
																		 <<"ems-catalog">> => ServiceName,
																		 <<"ems-owner">> => ServiceOwner},
													 response_data = ems_schema:to_json({error, einvalid_rec_message}),
													 latency = ems_util:get_milliseconds() - T1}}
				after Timeout + 3000 ->
					?DEBUG("ems_dispatcher received a timeout while waiting ~pms for the result of a service from ~p.", [Timeout, {Module, Node}]),
					ems_db:inc_counter(ServiceTimeoutMetricName),
					{error, request, Request#request{code = 503,
													 reason = etimeout_service,
													 content_type = ?CONTENT_TYPE_JSON,
													 service = Service,
													 params_url = ParamsMap,
													 querystring_map = QuerystringMap,
													 response_header = #{<<"ems-node">> => NodeBin,
																		 <<"ems-catalog">> => ServiceName,
																		 <<"ems-owner">> => ServiceOwner},
													 response_data = ems_schema:to_json({error, etimeout_service}),
													 latency = ems_util:get_milliseconds() - T1}}
			end;
		Error ->  
			ems_db:inc_counter(ServiceUnavailableMetricName),
			Error
	end.
		

get_work_node('', _, _, _, _) -> {ok, node()};
get_work_node([], _, _, _, _) -> {error, eunavailable_service};
get_work_node([_|T], HostList, HostNames, ModuleName, Tentativa) -> 
	QtdHosts = length(HostList),
	case QtdHosts == 1 of
		true -> Node = hd(HostList);
		false ->
			% ========= faz round robin ===========
			%% Localiza a entrada do módulo na tabela hash
			case ets:lookup(ctrl_node_dispatch, ModuleName) of
				[] -> 
					% não encontrou, vamos selecionar o primeiro host mas o próximo será o segundo
					Index = 2,
					Node = hd(HostList);
				[{_, Idx}] -> 
					% Se o idx não existe pega o primeiro e o próximo será o segundo
					case Idx > QtdHosts of
						true -> 
							Index = 2,
							Node = hd(HostList);
						false -> 
							Node = lists:nth(Idx, HostList),
							Index = Idx + 1
					end
			end,
			% Inserimos na tabela hash os dados de controle
			ets:insert(ctrl_node_dispatch, {ModuleName, Index})
	end,

	
	% Este node está vivo? Temos que rotear para um node existente
	Ping = net_adm:ping(Node),
	case Ping of
		pong -> {ok, Node};
		pang -> get_work_node(T, HostList, HostNames, ModuleName, Tentativa)
	end.
		


-spec dispatch_middleware_function(#request{}) -> {ok, request, #request{}} | {error, request, #request{}}.
dispatch_middleware_function(Request = #request{reason = ok,
												req_hash = ReqHash,
												t1 = T1,
												type = Type,
												service = Service = #service{middleware = Middleware,
																			 result_cache = ResultCache,
																			 service_error_metric_name = ServiceErrorMetricName}}) ->
	try
		case Middleware of 
			undefined -> Result = {ok, Request};
			_ ->
				case code:ensure_loaded(Middleware) of
					{module, _} ->
						Result = case erlang:function_exported(Middleware, onrequest, 1) of
									true -> apply(Middleware, onrequest, [Request]);
									false -> {ok, Request}
								 end;
					_ ->  Result = {error, einvalid_middleware}
				end
		end,
		case Result of
			{ok, Request2 = #request{response_header = ResponseHeader}} ->
				case Type =:= <<"GET">> of
					true -> 
						case ResultCache > 0 of
							true ->
								Request3 = Request2#request{response_header = ResponseHeader#{<<"ems-result-cache">> => integer_to_binary(ResultCache)},
															latency = ems_util:get_milliseconds() - T1},
								ems_cache:add(ets_result_cache_get, ResultCache, ReqHash, {T1, Request3, ResultCache}),
								{ok, request, Request3};
							_ -> 
								{ok, request, Request2#request{response_header = ResponseHeader#{<<"ems-result-cache">> => <<"0"/utf8>>},
															   latency = ems_util:get_milliseconds() - T1}}
						end;
					false ->
						ems_cache:flush(ets_result_cache_get),
						{ok, request, Request2#request{latency = ems_util:get_milliseconds() - T1}}
				end;
			{error, Reason2} = Error ->
				ems_db:inc_counter(ServiceErrorMetricName),	
				{error, request, Request#request{code = 500,
											     reason = Reason2,
												 content_type = ?CONTENT_TYPE_JSON,
												 service = Service,
												 response_data = ems_schema:to_json(Error),
												 latency = ems_util:get_milliseconds() - T1}}
		end
	catch 
		_Exception:Error2 -> 
			ems_db:inc_counter(ServiceErrorMetricName),
			{error, request, Request#request{code = 500,
											 reason = Error2,
											 content_type = ?CONTENT_TYPE_JSON,
											 service = Service,
											 response_data = ems_schema:to_json(Error2),
											 latency = ems_util:get_milliseconds() - T1}}
	end;
dispatch_middleware_function(Request = #request{code = Code, 
												t1 = T1, 
											    service = #service{service_error_metric_name = ServiceErrorMetricName}}) ->
	ems_db:inc_counter(ServiceErrorMetricName),								
	{error, request, Request#request{code = Code,
									 content_type = ?CONTENT_TYPE_JSON,
									 latency = ems_util:get_milliseconds() - T1}}.

									 	
