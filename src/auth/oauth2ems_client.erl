-module(oauth2ems_client).

-export([callback/1]).
-include("../include/ems_schema.hrl").
-define(REDIRECT_URI, <<"https://127.0.0.1:2302/callback">>).
-define(CLIENTID, <<"q1w2e3">>).
-define(SECRET, <<"123456">>).
-define(ACCESS_TOKEN_URL, "https://127.0.0.1:2302/authorize").
-define(SERVICO, <<"https://127.0.0.1:2302/netadm/info">>).

callback(Request) -> 

	Error = ems_request:get_querystring(<<"error">>, <<>>, Request),
	case Error == <<"access_denied">> of
		true ->
			{ok, Request#request{code = 401, 
				response_data = "{error: access_denied}"}
			};
		false -> 
			Code = ems_request:get_querystring(<<"code">>, <<>>, Request),
			Auth = base64:encode(<<?CLIENTID/binary, ":", ?SECRET/binary>>),
			Authz = <<"Basic ", Auth/binary>>,
			Authorization = binary:bin_to_list(Authz),
			Databin =  <<"grant_type=authorization_code&code=", Code/binary, "&redirect_uri=", ?REDIRECT_URI/binary>>,
			Data = binary:bin_to_list(Databin),			
			{ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} = 
				httpc:request(post,{?ACCESS_TOKEN_URL, [{"Authorization", Authorization}], "application/x-www-form-urlencoded",Data}, [], []),
			{ResponseData} = jiffy:decode(Body),
			AccessToken = proplists:get_value(<<"access_token">>,ResponseData),
            RefreshToken = proplists:get_value(<<"reflesh_token">>, ResponseData),
            Response = acessa_servico(AccessToken),
   			%Response2 = ems_schema:prop_list_to_json(Response),
			{ok, Request#request{code = 200, 
								 response_data = Response,
								 content_type = <<"application/json;charset=UTF-8">>}
			}
end.

acessa_servico(Token) ->
	URLbin =  <<?SERVICO/binary, "?access_token=", Token/binary>>,
	URL = binary:bin_to_list(URLbin),			
	{ok, {{_Version, 200, _ReasonPhrase}, _Headers, Net}} = 
		httpc:request(get,{URL, []}, [], []),
	Net.	



