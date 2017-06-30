-module(oauth2ems_client).

-export([callback/1]).
-include("../include/ems_schema.hrl").
-define(REDIRECT_URI, <<"http://127.0.0.1:2301/callback">>).
-define(CLIENTID, <<"q1w2">>).
-define(SECRET, <<"123456">>).
-define(ACCESS_TOKEN_URL, "https://127.0.0.1:2302/authorize").
-define(SERVICO, <<"https://127.0.0.1:2302/netadm/info">>).
-define(SCOPE, <<>>).

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
	{ok, {{_Version, 200, _ReasonPhrase}, _Headers, Net}} = 
		httpc:request(get,{URL, []}, [], []),
	Net.	

request(Authorization,Data)->
	Response = httpc:request(post,{?ACCESS_TOKEN_URL, [{"Authorization", Authorization}], "application/x-www-form-urlencoded",Data}, [], []),		
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
  {ok, Request#request{code = 401, 
								 response_data = Reason,
								 content_type = <<"application/json;charset=UTF-8">>}
	}.




