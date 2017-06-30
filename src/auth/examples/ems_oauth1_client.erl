-module(ems_oauth1_client).

-export([callback/1, cb/1]).
-include("../include/ems_schema.hrl").
-define(OAUTH_CALLBACK, <<"https://127.0.0.1:2302/cliente1">>).
-define(OAUTH_VERSION, <<"1.0">>).
-define(CONSUMER_KEY, <<"key">>).
-define(CONSUMER_SECRET, <<"secret">>).
-define(OAUTH_SIGNATURE_METHOD, <<"HMAC-SHA1">>).
-define(ACCESS_TOKEN_TMP, "https://127.0.0.1:2302/oauth/request_temp_credentials").
-define(ACCESS_TOKEN_URL, "https://127.0.0.1:2302/oauth/access_token").
-define(SERVICO, "https://127.0.0.1:2302/netadm/info").
-define(AUTHZ_PAGE, <<"https://127.0.0.1:2302/login/index.html">>).

-define(TOKEN_TABLE, cli_tokens).

callback(Request) ->
	Error = ems_request:get_querystring(<<"error">>, <<>>, Request),
	case Error == <<"access_denied">> of
		true -> bad(Request, "access_denied");
		false -> 
			Consumer = {?CONSUMER_KEY,?CONSUMER_SECRET,?OAUTH_SIGNATURE_METHOD},
			ParamsBin =  <<"oauth_consumer_key=", ?CONSUMER_KEY/binary, "&oauth_callback=", ?OAUTH_CALLBACK/binary,
			 "&oauth_signature_method=", ?OAUTH_SIGNATURE_METHOD/binary,"&oauth_version=",?OAUTH_VERSION/binary>>,
			{ok, Data} = format(ParamsBin,Consumer,?ACCESS_TOKEN_TMP,""),
			case request(?ACCESS_TOKEN_TMP,Data) of
				{ok, AccessToken,TokenSecret} -> 
					{ok, Path} = save_token(AccessToken,TokenSecret),
					redirect(Request, ?AUTHZ_PAGE, Path);
				_ ->	bad(Request, "access_denied")				
			end			
end.

cb(Request) -> 
	Verifier = ems_request:get_querystring(<<"oauth_verifier">>, <<>>, Request),
	Token = ems_request:get_querystring(<<"oauth_token">>, <<>>, Request),
	case Verifier == <<>> of
		true -> bad(Request, "access_denied");
		false -> 
			Consumer = {?CONSUMER_KEY,?CONSUMER_SECRET,?OAUTH_SIGNATURE_METHOD},
			ParamsBin =  <<"oauth_consumer_key=", ?CONSUMER_KEY/binary, "&oauth_callback=", ?OAUTH_CALLBACK/binary,"&oauth_signature_method=", ?OAUTH_SIGNATURE_METHOD/binary,
			"&oauth_verifier=", Verifier/binary,"&oauth_version=",?OAUTH_VERSION/binary, "&oauth_token=",Token/binary>>,
			{ok, Data} = format(ParamsBin,Consumer,Token),
			case request(?ACCESS_TOKEN_URL,Data) of
				{ok, AccessToken, TokenSecret} -> 
				io:format("\n AccessToken = ~s \n",[erlang:is_binary(AccessToken)]),
				PathBin =  <<"oauth_consumer_key=", ?CONSUMER_KEY/binary, "&oauth_signature_method=", ?OAUTH_SIGNATURE_METHOD/binary,
					"&oauth_version=",?OAUTH_VERSION/binary, "&oauth_token=",AccessToken/binary>>,
					{ok, Path} = format(PathBin,Consumer,?SERVICO,TokenSecret),
					redirect(Request, ?SERVICO, Path);
				_ ->	bad(Request, "access_denied")				
			end
					
end.

%%%===================================================================
%%% Funções internas
%%%===================================================================

save_token(AccessToken, RequestSecret) ->
	Context = [{<<"oauth_token_secret">>, RequestSecret}],
    put(?TOKEN_TABLE,AccessToken,Context),
    {ok, <<"oauth_token=",AccessToken/binary>>}.

resolve_token(AccessToken) ->
    case get(?TOKEN_TABLE, AccessToken) of
       {ok,Value} -> {ok,Value};
        _Error -> {error, invalid_token} 
    end.

%service(Token) ->
%	URLbin =  <<?SERVICO/binary, "?access_token=", Token/binary>>,
%	URL = binary:bin_to_list(URLbin),			
%	{ok, {{_Version, 200, _ReasonPhrase}, _Headers, Net}} = 
%		httpc:request(get,{URL, []}, [], []),
%	Net.	

request(URI,Data)->
	Response = httpc:request(post,{URI, [], "application/x-www-form-urlencoded",Data}, [], []),
	get_token(Response).


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

get_token({ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}})->
	Params = oauth:uri_params_decode(Body),
	AccessToken = erlang:list_to_binary(proplists:get_value("oauth_token",Params)),
	TokenSecret = erlang:list_to_binary(proplists:get_value("oauth_token_secret",Params)),
	{ok, AccessToken,TokenSecret};
	
get_token(_Error)-> {error, "access_denied"}.

bad(Request, Reason) ->
	{error, Request#request{code = 401, 
		response_data = list_to_binary("Bad Request: " ++ Reason)}
	}.
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

