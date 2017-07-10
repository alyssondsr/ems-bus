-module(oauth2mac_client).

-export([callback/1]).
-include("../include/ems_schema.hrl").
-define(REDIRECT_URI, <<"https://127.0.0.1:2302/callback">>).
-define(CLIENTID, <<"key">>).
-define(SECRET, <<"secret">>).
-define(OAUTH_VERSION, <<"1.0">>).
-define(ACCESS_TOKEN_URL, "https://127.0.0.1:2302/authorize").
-define(SERVICO, "https://127.0.0.1:2302/netadm/info").
-define(OAUTH_SIGNATURE_METHOD, <<"HMAC-SHA1">>).
-define(SCOPE, <<>>).
-define(TOKEN_TABLE, cli_tokens).

%-define(REDIRECT_URI, <<"https://164.41.120.42:2302/callback">>).
%-define(CLIENTID, <<"43138f88cb30a7b692f0">>).
%-define(SECRET, <<"b45266981d747535974047853c2bb8ab5bba01bd">>).
%-define(ACCESS_TOKEN_URL, "https://github.com/login/oauth/access_token").
%-define(SERVICO, <<"https://api.github.com/user">>).


callback(Request) -> 
	Code = ems_request:get_querystring(<<"code">>, <<>>, Request),
	case Code == <<>> of
		true ->
			{ok, Request#request{code = 401, 
				response_data = "{error: access_denied}"}
			};
		false -> 
			Consumer = {?CLIENTID,?SECRET,?OAUTH_SIGNATURE_METHOD},
			Auth = base64:encode(<<?CLIENTID/binary, ":", ?SECRET/binary>>),
			Authz = <<"Basic ", Auth/binary>>,
			Authorization = binary:bin_to_list(Authz),
			Databin =  <<"grant_type=authorization_code&code=", Code/binary, "&redirect_uri=", ?REDIRECT_URI/binary, "&client_id=",?CLIENTID/binary, "&client_secret=",?SECRET/binary, "&scope=", ?SCOPE/binary>>,
			Data = binary:bin_to_list(Databin),
			io:format("\n Data = ~s \n",[Data]),
			case request(?ACCESS_TOKEN_URL,Data) of
				{ok, AccessToken, TokenSecret} -> 
					io:format("\n AccessToken = ~s \n",[AccessToken]),
					PathBin =  <<"oauth_consumer_key=", ?CLIENTID/binary, "&oauth_signature_method=", ?OAUTH_SIGNATURE_METHOD/binary,
					"&oauth_version=",?OAUTH_VERSION/binary, "&oauth_token=",AccessToken/binary>>,
					{ok, Path} = format(PathBin,Consumer,?SERVICO,TokenSecret),
					redirect(Request, ?SERVICO, Path);
				_ ->	bad(Request, "access_denied")				
				
			end			
end.

%%%===================================================================
%%% Funções internas
%%%===================================================================

acessa_servico(Token) ->
	URLbin =  <<?SERVICO/binary, "?access_token=", Token/binary>>,
	URL = binary:bin_to_list(URLbin),			
	{ok, {{_Version, 200, _ReasonPhrase}, _Headers, Net}} = 
		httpc:request(get,{URL, []}, [], []),
	Net.	

request(URI,Data)->
	Response = httpc:request(post,{URI, [], "application/x-www-form-urlencoded",Data}, [], []),
	get_token(Response).

get_token({ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}})->
	Params = oauth:uri_params_decode(Body),
	AccessToken = erlang:list_to_binary(proplists:get_value("oauth_token",Params)),
	TokenSecret = erlang:list_to_binary(proplists:get_value("oauth_token_secret",Params)),
	{ok, AccessToken,TokenSecret};
	
get_token(_Error)-> {error, "access_denied"}.

format(ParamsBin, Consumer, Token) -> 
	{ok, GrantCtx} = resolve_token(Token),
	Secret = get_(GrantCtx,<<"oauth_token_secret">>),
	format(ParamsBin, Consumer,?ACCESS_TOKEN_URL,Secret).

format(ParamsBin, Consumer, URL, Secret) -> 
	Params = oauth:uri_params_decode(binary:bin_to_list(ParamsBin)),
	Signature = oauth:hmac_sha1_signature("POST", URL, Params, Consumer, Secret),
	SigEncode = list_to_binary(percent:url_encode(Signature)),
	io:format("\n Signature Transmit: ~p \n",[Signature]),
	Databin =  <<ParamsBin/binary,"&oauth_signature=", SigEncode/binary>>,
	{ok, binary:bin_to_list(Databin)}.


redirect(Request, RedirectUri, Path) when is_list(Path)->
	PathBin = list_to_binary(Path),
	RedirBin= list_to_binary(RedirectUri),
	LocationPath = <<RedirBin/binary,"?",PathBin/binary>>,
	io:format("\n LocationPath = ~s\n",[LocationPath]),
	{ok, Request#request{code = 302, 
		 response_data = <<"{}">>,
		 response_header = #{
					<<"location">> => LocationPath
					}
		}
	};
redirect(Request, RedirectUri, Path) ->
	LocationPath = <<RedirectUri/binary,"?",Path/binary>>,
	{ok, Request#request{code = 302, 
		 response_data = <<"{}">>,
		 response_header = #{
					<<"location">> => LocationPath
					}
		}
	}.
	
	save_token(AccessToken, RequestSecret) ->
	Context = [{<<"oauth_token_secret">>, RequestSecret}],
    put(?TOKEN_TABLE,AccessToken,Context),
    {ok, <<"oauth_token=",AccessToken/binary>>}.

resolve_token(AccessToken) ->
    case get(?TOKEN_TABLE, AccessToken) of
       {ok,Value} -> {ok,Value};
        _Error -> {error, invalid_token} 
    end.



ok(Request, Body) ->
			{ok, Request#request{code = 200, 
								 response_data = Body,
								 content_type = <<"application/json;charset=UTF-8">>}
			}.		
bad(Request, Reason) ->
  {ok, Request#request{code = 401, 
								 response_data = Reason,
								 content_type = <<"application/json;charset=UTF-8">>}
	}.


put(Table, Key, Value) ->
    ets:insert(Table, {Key, Value}),
    ok.

get(Table, Key) ->
    case ets:lookup(Table, Key) of
        [] ->
            {error, notfound};
        [{_Key, Value}] ->
            {ok, Value}
    end.

get_(O, K) ->
    {ok, V} = get(O, K, []),
    V.

get(O, K, _)  ->
    case lists:keyfind(K, 1, O) of
        {K, V} -> {ok, V};
        false  -> {error, notfound}
    end.



