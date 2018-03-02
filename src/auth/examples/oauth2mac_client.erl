-module(oauth2mac_client).

-export([callback/1]).
-include("../include/ems_schema.hrl").
-define(REDIRECT_URI, <<"https://127.0.0.1:2344/callback1">>).
-define(CLIENTID, <<"key">>).
-define(SECRET, <<"secret">>).
-define(OAUTH_VERSION, <<"1.0">>).
-define(ACCESS_TOKEN_URL, "https://127.0.0.1:2344/authorize").
-define(SERVICO, "https://127.0.0.1:2344/netadm/info").
-define(OAUTH_SIGNATURE_METHOD, <<"HMAC-SHA1">>).
-define(SCOPE, <<>>).
-define(TOKEN_TABLE, cli_tokens).

callback(Request) -> 
	Code = ems_request:get_querystring(<<"code">>, <<>>, Request),
	case Code == <<>> of
		true -> 	bad(Request, "access_denied");
		false -> 
			Consumer = {?CLIENTID,?SECRET,?OAUTH_SIGNATURE_METHOD},
			Databin =  <<"grant_type=mac&code=", Code/binary, "&redirect_uri=", ?REDIRECT_URI/binary, "&client_id=",?CLIENTID/binary, "&client_secret=",?SECRET/binary, "&scope=", ?SCOPE/binary>>,
			Data = binary:bin_to_list(Databin),
			case request(?ACCESS_TOKEN_URL,Data) of
				{ok, AccessToken, TokenSecret} -> 
					Nonce = binary:bin_to_list(base64:encode(crypto:strong_rand_bytes(5))),
					NonceEncode = list_to_binary(percent:url_encode(Nonce)),
					PathBin =  <<"oauth_consumer_key=", ?CLIENTID/binary, "&oauth_signature_method=", ?OAUTH_SIGNATURE_METHOD/binary,
					"&oauth_version=",?OAUTH_VERSION/binary, "&oauth_token=",AccessToken/binary, "&oauth_nonce=",NonceEncode/binary>>,
					{ok, Path} = format(PathBin,Consumer,?SERVICO,TokenSecret),
					redirect(Request, ?SERVICO, Path);
				_ ->	bad(Request, "access_denied")				
				
			end			
end.

%%%===================================================================
%%% Funções internas
%%%===================================================================


request(URI,Data)->
	Response = httpc:request(post,{URI, [], "application/x-www-form-urlencoded",Data}, [], []),
	get_token(Response).

get_token({ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}})->
	{ResponseData} = jiffy:decode(Body),
	AccessToken = proplists:get_value(<<"access_token">>,ResponseData),
	TokenSecret = proplists:get_value(<<"token_secret">>,ResponseData),
	{ok, AccessToken,TokenSecret};
	
get_token(_Error)-> {error, "access_denied"}.

format(ParamsBin, Consumer, URL, Secret) -> 
	Params = oauth:uri_params_decode(binary:bin_to_list(ParamsBin)),
	%io:format("\n\n\n Params SRC ~p \n\n\n",[Params]),
	Signature = oauth:hmac_sha1_signature("POST", URL, Params, Consumer, Secret),
	SigEncode = list_to_binary(percent:url_encode(Signature)),
	Databin =  <<ParamsBin/binary,"&oauth_signature=", SigEncode/binary>>,
	{ok, binary:bin_to_list(Databin)}.



redirect(Request, RedirectUri, Path) when is_list(Path)->
	PathBin = list_to_binary(Path),
	RedirBin= list_to_binary(RedirectUri),
	LocationPath = <<RedirBin/binary,"?",PathBin/binary>>,
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

bad(Request, Reason) ->
	{error, Request#request{code = 401, 
								 response_data = Reason,
								 content_type_out = <<"application/json;charset=UTF-8">>}
	}.


