-module(oauth2ems_client).

-export([callback/1]).
-include("../include/ems_schema.hrl").
-define(REDIRECT_URI, <<"http://127.0.0.1:2301/callback">>).
-define(CLIENTID, <<"q1w2e3">>).
-define(SECRET, <<"123456">>).
-define(ACCESS_TOKEN_URL, "https://127.0.0.1:2302/authorize").
-define(SERVICO, "https://localhost:2302/netadm/info").

callback(Request) -> 

	Error = ems_request:get_querystring(<<"error">>, <<>>, Request),
	case Error == <<"access_denied">> of
		true ->
			{ok, Request#request{code = 401, 
				response_data = "{error: access_denied}"}
			};
		false -> 
			Code = ems_request:get_querystring(<<"code">>, <<>>, Request),
			RedirectUri = ?REDIRECT_URI,
			Auth = base64:encode(<<?CLIENTID/binary, ":", ?SECRET/binary>>),
			Authz = <<"Basic ", Auth/binary>>,
			Authorization = binary:bin_to_list(Authz),
			Databin =  <<"grant_type=authorization_code&code=", Code/binary, "&redirect_uri=", ?REDIRECT_URI/binary>>,
			Data = binary:bin_to_list(Databin),			

			{ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} = 
				httpc:request(post,{?ACCESS_TOKEN_URL, [{"Authorization", Authorization}], "application/x-www-form-urlencoded",Data}, [], []),
			io:format("\n________________\n ~s \n________________\n",[Body]),
			Teste = jiffy:decode(Body),

			AccessToken = lists:keyfind(<<"access_token">>,1, Teste),
            RefreshToken = proplists:get_value(<<"scope">>, Teste),
   			io:format("\n________________\n ~s \n________________\n",[AccessToken]),
   			io:format("\n________________\n ~s \n________________\n",[RefreshToken]),

            net_adm(AccessToken)           
end.

net_adm(Token) ->
	URLbin =  <<?SERVICO/binary, "?access_token=", Token/binary>>,
	URL = binary:bin_to_list(URLbin),			
	{ok, {{_Version, 200, _ReasonPhrase}, _Headers, Net}} = 
		httpc:request(get,{URL, []}, [], []),
	io:format("\n________________\n ~s \n________________\n",[Net]),
	Net.	



