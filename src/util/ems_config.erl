%%********************************************************************
%% @title Module ems_config
%% @version 1.0.0
%% @doc Module for configuration management
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_config).

-behavior(gen_server). 

-include("../../include/ems_config.hrl").
-include("../../include/ems_schema.hrl").

%% Server API
-export([start/0, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3]).

-export([getConfig/0, getConfig/3, get_port_offset/1, select_config_file/2]).

-define(SERVER, ?MODULE).

%%====================================================================
%% Server API
%%====================================================================

start() -> 
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).
 
stop() ->
    gen_server:cast(?SERVER, shutdown).
 

%%====================================================================
%% Client API
%%====================================================================
 
getConfig() -> gen_server:call(?SERVER, get_config).

-spec getConfig(binary(), binary(), any()) -> any().
getConfig(ParamName, ServiceName, Default) -> gen_server:call(?SERVER, {get_config, ParamName, ServiceName, Default}).

-spec get_port_offset(#service{}) -> non_neg_integer() | undefined.
get_port_offset(S = #service{tcp_port = Port, name = ServiceName}) ->
	Port2 = gen_server:call(?SERVER, {use_port_offset, ServiceName, Port}),
 	S#service{tcp_port = Port2}.



%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init([]) -> 
	try
		ets:new(debug_ets, [set, named_table, public, {read_concurrency, true}, {write_concurrency, false}]),
		ets:insert(debug_ets, {debug, false}),
		Config = load_config(),
		{ok, Config}
	catch _Exception: Reason ->
		{stop, Reason}
	end.

    
handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast(_Msg, State) ->
	{noreply, State}.
    
handle_call(get_config, _From, State) ->
	{reply, State, State};

handle_call({get_config, ParamName, ServiceName, Default}, _From, State = #config{params = Params}) ->
	ParamName2 = iolist_to_binary([ServiceName, <<".">>, ParamName]),
	Result = maps:get(ParamName2, Params, Default),
	{reply, Result, State};

handle_call({use_port_offset, <<>>}, _From, State) ->
	{reply, undefined, State};
handle_call({use_port_offset, ServiceName, DefaultPort}, _From, State = #config{params = Params}) ->
	ParamName = iolist_to_binary([ServiceName, <<"_port_offset">>]),
	Port = maps:get(ParamName, Params, DefaultPort) ,
	Params2 = maps:put(ParamName, Port + 1, Params),
	State2 = State#config{params = Params2},
	{reply, Port, State2}.

handle_info(_Msg, State) ->
   {noreply, State}.

handle_info(State) ->
   {noreply, State}.

terminate(_Reason, _State) ->
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
    
    
%%====================================================================
%% Funções internas
%%====================================================================

% Returns the configuration file data
% Locais do arquivo: home do user (.erlangms/node@hostname.conf, .erlangms/emsbus.conf) ou na pasta priv/conf do barramento
-spec get_config_data() -> string() | {error, enofile_config}.
get_config_data() ->
	try
		ConfigFile = case init:get_argument(conf) of
								{ok, [[ConfigFileCommandLine]]} -> ConfigFileCommandLine;
								_ -> "emsbus.conf"
							end,
		Filename = select_config_file(ConfigFile, ?CONF_FILE_PATH),
		case file:read_file(Filename) of 
			{ok, Arq} -> {ok, Arq, Filename};
			_ -> {error, enofile_config}
		end
	catch
		_:_ -> {error, enofile_config}
	end.

print_config_settings(Json = #config{ems_debug = true, config_file = Filename}) ->
	ems_logger:format_alert("\nems_config loading configuration file ~p...\n", [Filename]),
	ems_logger:format_debug("~p\n", [Json]);
print_config_settings(#config{ems_debug = false, config_file = Filename}) ->
	ems_logger:format_alert("\nems_config loading configuration file ~p...\n", [Filename]).

% Load the configuration file
load_config() ->
	case get_config_data() of
		{ok, ConfigData, Filename} ->
			case ems_util:json_decode_as_map(ConfigData) of
				{ok, Json} -> 
					try
						Result = parse_config(Json, Filename),
						print_config_settings(Result),
						Result
					catch 
						_Exception:Reason ->
							ems_logger:format_warn("\nems_config parse invalid configuration file ~p. Reason: ~p. Running with default settings.\n", [Filename, Reason]),
							get_default_config()
					end;
				_Error -> 
					ems_logger:format_warn("\nems_config parse invalid configuration file ~p. Running with default settings.\n", [Filename]),
					get_default_config()
			end;
		{error, enofile_config} ->
			ems_logger:format_warn("Configuration file does not exist or can not be read, using default settings.\n"),
			get_default_config()
	end.

% parse path_search and return a list
-spec parse_cat_path_search(map()) -> list().
parse_cat_path_search(Json) ->
	CatPathSearch = maps:get(<<"catalog_path">>, Json, #{}),
	CatPathSearch2 = case maps:is_key(<<"ems-bus">>, CatPathSearch) of
						true -> maps:to_list(CatPathSearch);
						false -> maps:to_list(CatPathSearch) 
					end,
	[{K, binary_to_list(V)} || {K,V} <- CatPathSearch2] ++ [{<<"ems-bus">>, ?CATALOGO_ESB_PATH}].


-spec parse_static_file_path(map()) -> list().
parse_static_file_path(Json) ->
	StaticFilePath = maps:get(<<"static_file_path">>, Json, #{}),
	StaticFilePathList = maps:to_list(StaticFilePath),
	StaticFilePathList2 = [{<<"login_path">>, list_to_binary(?STATIC_FILE_PATH ++ "/login")} | StaticFilePathList],
	StaticFilePathList3 = [{<<"www_path">>, list_to_binary(?STATIC_FILE_PATH)} | StaticFilePathList2],
	[{K, ems_util:remove_ult_backslash_url(binary_to_list(V))} || {K, V} <- StaticFilePathList3].
	

parse_datasources([], _, Result) -> maps:from_list(Result);
parse_datasources([DsName|T], Datasources, Result) ->
	M = maps:get(DsName, Datasources),
	Ds = ems_db:create_datasource_from_map(M, undefined, #{}),
	parse_datasources(T, Datasources, [{DsName, Ds} | Result]).
								
	
parse_datasources(Json) ->
	Datasources = maps:get(<<"datasources">>, Json, #{}),
	parse_datasources(maps:keys(Datasources), Datasources, []).
	
	
parse_tcp_allowed_address(undefined) -> all;
parse_tcp_allowed_address([<<"*.*.*.*">>]) -> all;
parse_tcp_allowed_address(V) -> V.

parse_http_headers(HttpHeaders, ShowDebugResponseHeaders) ->
	parse_http_headers_(maps:to_list(HttpHeaders), ShowDebugResponseHeaders, []).

parse_http_headers_([], ShowDebugResponseHeaders, Result) ->
	HttpHeaders = maps:from_list(Result),
	HttpHeaders1 = maps:remove(<<"ems-node">>, HttpHeaders),
	case ShowDebugResponseHeaders of
		true -> HttpHeaders1#{<<"ems-node">> => ems_util:node_binary()};
		false -> HttpHeaders1
	end;
parse_http_headers_([{Key, Value} = Item|T], ShowDebugResponseHeaders, Result) when is_binary(Value) ->
	case byte_size(Key) =< 100 andalso Value =/= undefined andalso Value =/= <<>> andalso byte_size(Value) =< 450 of
		true -> 
			parse_http_headers_(T, ShowDebugResponseHeaders, [Item | Result]);
		false -> 
			erlang:error(einvalid_http_response_header)
	end;
parse_http_headers_([{Key, _} = Item|T], ShowDebugResponseHeaders, Result) ->
	case byte_size(Key) =< 100 of
		true -> 
			parse_http_headers_(T, ShowDebugResponseHeaders, [Item | Result]);
		false -> 
			erlang:error(einvalid_http_response_header)
	end.
	


-spec parse_config(map(), string()) -> #config{}.
parse_config(Json, NomeArqConfig) ->
	{ok, Hostname} = inet:gethostname(),
	Hostname2 = list_to_binary(Hostname),
	TcpListenAddress = maps:get(<<"tcp_listen_address">>, Json, [<<"0.0.0.0">>]),
	TcpListenAddress_t = ems_util:parse_tcp_listen_address(TcpListenAddress),
 	{TcpListenMainIp, TcpListenMainIp_t} = get_tcp_listen_main_ip(TcpListenAddress_t),
 	ShowDebugResponseHeaders = ems_util:parse_bool(maps:get(<<"show_debug_response_headers">>, Json, false)),
	HttpHeaders0 = maps:merge(?HTTP_HEADERS_DEFAULT, maps:get(<<"http_headers">>, Json, #{})),
	HttpHeadersOptions0 = maps:merge(?HTTP_HEADERS_DEFAULT, maps:get(<<"http_headers_options">>, Json, #{})),
	HttpHeaders = parse_http_headers(HttpHeaders0, ShowDebugResponseHeaders),
	HttpHeadersOptions = parse_http_headers(HttpHeadersOptions0, ShowDebugResponseHeaders),
	#config{ cat_host_alias = maps:get(<<"host_alias">>, Json, #{<<"local">> => Hostname2}),
			 cat_host_search = maps:get(<<"host_search">>, Json, <<>>),							
			 cat_node_search = maps:get(<<"node_search">>, Json, <<>>),
			 cat_path_search = parse_cat_path_search(Json),
			 static_file_path = parse_static_file_path(Json),
			 cat_disable_services = maps:get(<<"disable_services">>, Json, []),
			 cat_enable_services = maps:get(<<"enable_services">>, Json, []),
			 cat_disable_services_owner = maps:get(<<"disable_services_owner">>, Json, []),
			 cat_enable_services_owner = maps:get(<<"enable_services_owner">>, Json, []),
			 cat_restricted_services_owner = maps:get(<<"restricted_services_owner">>, Json, []),
			 cat_restricted_services_admin = maps:get(<<"restricted_services_admin">>, Json, []),
			 ems_hostname = Hostname2,
			 ems_host = list_to_atom(Hostname),
			 ems_file_dest = NomeArqConfig,
			 ems_debug = ems_util:parse_bool(maps:get(<<"debug">>, Json, false)),
			 ems_result_cache = ems_util:parse_result_cache(maps:get(<<"result_cache">>, Json, ?TIMEOUT_DISPATCHER_CACHE)),
			 ems_datasources = parse_datasources(Json),
			 show_debug_response_headers = ShowDebugResponseHeaders,
			 tcp_listen_address	= TcpListenAddress,
			 tcp_listen_address_t = TcpListenAddress_t,
			 tcp_listen_main_ip = TcpListenMainIp,
			 tcp_listen_main_ip_t = TcpListenMainIp_t,
			 tcp_allowed_address = parse_tcp_allowed_address(maps:get(<<"tcp_allowed_address">>, Json, all)),
			 http_max_content_length = ems_util:parse_range(maps:get(<<"http_max_content_length">>, Json, ?HTTP_MAX_CONTENT_LENGTH), 0, ?HTTP_MAX_CONTENT_LENGTH_BY_SERVICE),
			 http_headers = HttpHeaders,
			 http_headers_options = HttpHeadersOptions,
			 authorization = ems_util:parse_authorization_type(maps:get(<<"authorization">>, Json, ?AUTHORIZATION_TYPE_DEFAULT)),
			 oauth2_with_check_constraint = ems_util:parse_bool(maps:get(<<"oauth2_with_check_constraint">>, Json, false)),
			 oauth2_refresh_token = ems_util:parse_range(maps:get(<<"oauth2_refresh_token">>, Json, ?OAUTH2_DEFAULT_TOKEN_EXPIRY), 0, ?OAUTH2_MAX_TOKEN_EXPIRY),
			 config_file = NomeArqConfig,
			 params = Json,
			 client_path_search = select_config_file(<<"user_client.json">>, maps:get(<<"client_path_search">>, Json, ?CLIENT_PATH)),
			 user_path_search = select_config_file(<<"users.json">>, maps:get(<<"user_path_search">>, Json, ?USER_PATH)),
			 user_dados_funcionais_path_search = select_config_file(<<"user_dados_funcionais.json">>, maps:get(<<"user_dados_funcionais_path">>, Json, ?USER_DADOS_FUNCIONAIS_PATH)),
			 user_perfil_path_search = select_config_file(<<"user_perfil.json">>, maps:get(<<"user_perfil_path_search">>, Json, ?USER_PERFIL_PATH)),
			 user_permission_path_search = select_config_file(<<"user_permission.json">>, maps:get(<<"user_permission_path_search">>, Json, ?USER_PERMISSION_PATH)),
			 user_endereco_path_search = select_config_file(<<"user_endereco.json">>, maps:get(<<"user_endereco_path_search">>, Json, ?USER_ENDERECO_PATH)),
			 user_telefone_path_search = select_config_file(<<"user_telefone.json">>, maps:get(<<"user_telefone_path_search">>, Json, ?USER_TELEFONE_PATH)),
			 user_email_path_search	= select_config_file(<<"user_email.json">>, maps:get(<<"user_email_path_search">>, Json, ?USER_EMAIL_PATH)),
 			 ssl_cacertfile = maps:get(<<"ssl_cacertfile">>, Json, undefined),
			 ssl_certfile = maps:get(<<"ssl_certfile">>, Json, undefined),
			 ssl_keyfile = maps:get(<<"ssl_keyfile">>, Json, undefined),
			 sufixo_email_institucional = binary_to_list(maps:get(<<"sufixo_email_institucional">>, Json, <<"@unb.br">>)),
	 		 log_show_response = ems_util:parse_bool(maps:get(<<"log_show_response">>, Json, false)),
			 log_show_payload = ems_util:parse_bool(maps:get(<<"log_show_payload">>, Json, false)),
	 		 log_show_response_max_length = ems_util:parse_bool(maps:get(<<"log_show_response_max_length">>, Json, ?LOG_SHOW_RESPONSE_MAX_LENGTH)),
			 log_show_payload_max_length = ems_util:parse_bool(maps:get(<<"log_show_payload_max_length">>, Json, ?LOG_SHOW_PAYLOAD_MAX_LENGTH))
		}.

% It generates a default configuration if there is no configuration file
-spec get_default_config() -> #config{}.
get_default_config() ->
	{ok, Hostname} = inet:gethostname(),
	Hostname2 = list_to_binary(Hostname),
	TcpListenAddress = [<<"0.0.0.0">>],
	TcpListenAddress_t = ems_util:parse_tcp_listen_address(TcpListenAddress),
 	{TcpListenMainIp, TcpListenMainIp_t} = get_tcp_listen_main_ip(TcpListenAddress_t),
	#config{cat_host_alias				= #{<<"local">> => Hostname2},
			 cat_host_search			= <<>>,							
			 cat_node_search			= <<>>,
			 cat_path_search			= [{<<"ems-bus">>, ?CATALOGO_ESB_PATH}],
			 cat_disable_services		= [],
			 cat_enable_services		= [],
			 cat_disable_services_owner	= [],
			 cat_enable_services_owner	= [],
			 cat_restricted_services_owner = [],
			 cat_restricted_services_admin = [],
			 static_file_path			= [],
			 ems_hostname 				= Hostname2,
			 ems_host	 				= list_to_atom(Hostname),
			 ems_file_dest				= "",
			 ems_debug					= false,
			 ems_result_cache			= ?TIMEOUT_DISPATCHER_CACHE,
			 ems_datasources			= #{},
			 show_debug_response_headers		= false,
			 tcp_listen_address			= TcpListenAddress,
			 tcp_listen_address_t		= TcpListenAddress_t,
			 tcp_listen_main_ip 		= TcpListenMainIp,
			 tcp_listen_main_ip_t 		= TcpListenMainIp_t,
			 tcp_allowed_address		= all,
			 authorization				= oauth2,
			 oauth2_with_check_constraint = false,
			 oauth2_refresh_token 		= ?OAUTH2_DEFAULT_TOKEN_EXPIRY,
			 config_file			    = undefined,
			 params						= #{},
			 client_path_search			= ?CLIENT_PATH,
			 user_path_search			= ?USER_PATH,
			 user_dados_funcionais_path_search = ?USER_DADOS_FUNCIONAIS_PATH,
			 user_perfil_path_search	= ?USER_PERFIL_PATH,
			 user_permission_path_search	= ?USER_PERMISSION_PATH,
			 user_email_path_search	= ?USER_EMAIL_PATH,
			 user_endereco_path_search	= ?USER_ENDERECO_PATH,
			 user_telefone_path_search	= ?USER_TELEFONE_PATH,
			 http_max_content_length = ?HTTP_MAX_CONTENT_LENGTH,
			 http_headers = ?HTTP_HEADERS_DEFAULT,
			 http_headers_options = ?HTTP_HEADERS_DEFAULT,
			 ssl_cacertfile = undefined,
			 ssl_certfile = undefined,
			 ssl_keyfile = undefined,
			 sufixo_email_institucional = "@unb.br",
	 		 log_show_response = false,
			 log_show_payload = false,
	 		 log_show_response_max_length = ?LOG_SHOW_RESPONSE_MAX_LENGTH,
			 log_show_payload_max_length = ?LOG_SHOW_PAYLOAD_MAX_LENGTH
		}.

-spec select_config_file(binary() | string(), binary() | string()) -> {ok, string()} | {error, enofile_config}.
select_config_file(ConfigFile, ConfigFileDefault) ->
	ConfigFile2 = case is_binary(ConfigFile) of
					 true ->  binary_to_list(ConfigFile);
				  	 false -> ConfigFile
				  end,
	ConfigFileDefault2 = case is_binary(ConfigFileDefault) of
					 true ->  binary_to_list(ConfigFileDefault);
				  	 false -> ConfigFileDefault
				  end,
	HomePath = ems_util:get_home_dir(),
	Filename = lists:concat([HomePath, "/.erlangms/", ConfigFile2]),
	case file:read_file(Filename) of 
		{ok, _Arq} -> 
			?DEBUG("ems_config checking if node file configuration ~p exist: Ok", [Filename]),
			Filename;
		_ -> 
			?DEBUG("ems_config checking if node file configuration ~p exist: No", [Filename]),
			Filename2 = lists:concat([HomePath, "/.erlangms/", ConfigFile2]),
			case file:read_file(Filename2) of 
				{ok, _Arq2} -> 
					?DEBUG("ems_config checking if file configuration ~p exist: Ok", [Filename2]),
					Filename2;
				_ -> 
					?DEBUG("ems_config checking if file configuration ~p exist: No", [Filename2]),
					case file:read_file(ConfigFileDefault2) of 
						{ok, _Arq3} -> 
							?DEBUG("ems_config checking if global file configuration ~p exist: Ok", [ConfigFileDefault2]),
							ConfigFileDefault2;
						_ -> 
							?DEBUG("ems_config checking if global file configuration ~p exist: No", [ConfigFileDefault2]),
							erlang:error({error, enofile_config})
					end
			end
	end.


-spec get_tcp_listen_main_ip(list(tuple())) -> tuple().
get_tcp_listen_main_ip(TcpListenAddress_t) when length(TcpListenAddress_t) > 0 -> 
	Ip = lists:last(TcpListenAddress_t),
	{list_to_binary(inet:ntoa(Ip)), Ip};
get_tcp_listen_main_ip(_) -> {undefined, undefined}.


	

