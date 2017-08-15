-module(oauth2ems_client).

-export([callback/1]).
-include("../include/ems_schema.hrl").

%-define(REDIRECT_URI, <<"https://164.41.120.43:2302/callback">>).
%-define(CLIENTID, <<"q1w2e3">>).
%-define(SECRET, <<"123456">>).
%-define(ACCESS_TOKEN_URL, "https://164.41.120.34:2302/authorize").
%-define(SERVICO, <<"https://164.41.120.34:2302/netadm/info">>).
%-define(SCOPE, <<>>).

-define(REDIRECT_URI, <<"http://127.0.0.1:2301/callback">>).
-define(CLIENTID, <<"q1w2">>).
-define(SECRET, <<"123456">>).
-define(ACCESS_TOKEN_URL, "http://127.0.0.1:2301/authorize").
-define(SERVICO, <<"http://127.0.0.1:2301/netadm/info">>).
-define(SCOPE, <<"email">>).

%-define(REDIRECT_URI, <<"http://164.41.120.42:2301/callback">>).
%-define(CLIENTID, <<"43138f88cb30a7b692f0">>).
%-define(SECRET, <<"b45266981d747535974047853c2bb8ab5bba01bd">>).
%-define(ACCESS_TOKEN_URL, "https://github.com/login/oauth/access_token").
%-define(SERVICO, <<"https://api.github.com/user">>).
%-define(SCOPE, <<>>).


%-define(CLIENTID, <<"v3m7smtarlsk668">>).
%-define(SECRET, <<"	ljumioeejyn3p4a">>).
%-define(ACCESS_TOKEN_URL, "https://api.dropboxapi.com/oauth2/token").
%-define(SERVICO, <<"https://api.dropboxapi.com/2/users/get_current_account">>).
%-define(SCOPE, <<>>).


callback(Request) -> 
	Code = ems_request:get_querystring(<<"code">>, <<>>, Request),
	case Code == <<>> of
		true ->	bad(Request, <<"{error: access_denied}">>);
		false -> 
			Auth = base64:encode(<<?CLIENTID/binary, ":", ?SECRET/binary>>),
			Authz = <<"Basic ", Auth/binary>>,
			Authorization = binary:bin_to_list(Authz),
			Databin =  <<"grant_type=authorization_code&code=", Code/binary, "&redirect_uri=", ?REDIRECT_URI/binary, "&scope=", ?SCOPE/binary>>,
			Data = binary:bin_to_list(Databin),
			case request(Authorization,Data) of
				{ok,Response} -> ok(Request, Response);
				{error,_} -> bad(Request, <<"{error: access_denied}">>)				
			end			
end.

%%%===================================================================
%%% Funções internas
%%%===================================================================

acessa_servico(Token) ->
	URLbin =  <<?SERVICO/binary, "?access_token=", Token/binary>>,
	URL = binary:bin_to_list(URLbin),			
	{ok, {{_Version, _Status, _ReasonPhrase}, _Headers, Net}} = 
		httpc:request(get,{URL, []}, [], []),
	Net.	

request(Authorization,Data)->
	Response = httpc:request(post,{?ACCESS_TOKEN_URL, [{"Authorization", Authorization}], "application/x-www-form-urlencoded",Data}, [], []),		
	%io:format("\n\n\n Response ~s \n\n\n",[Response]),
	format(Response).

format({ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}})->
	{ResponseData} = jiffy:decode(Body),
	AccessToken = proplists:get_value(<<"access_token">>,ResponseData),
    %RefreshToken = proplists:get_value(<<"reflesh_token">>, ResponseData),
	{ok, acessa_servico(AccessToken)};
	
format(_Error)-> {error, "access_denied"}.

ok(Request, Body) ->
			{ok, Request#request{code = 200, 
								 response_data = Body,
								 content_type = <<"application/json;charset=UTF-8">>}
			}.		
bad(Request, Reason) ->
  {error, Request#request{code = 401, 
								 response_data = Reason,
								 content_type = <<"application/json;charset=UTF-8">>}
	}.




