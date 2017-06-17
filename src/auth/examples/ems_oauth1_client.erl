-module(ems_oauth1_client).

-export([callback/1]).
-include("../include/ems_schema.hrl").
-define(OAUTH_CALLBACK, <<"https://127.0.0.1:2302/callback">>).
-define(CONSUMER_KEY, <<"key">>).
-define(CONSUMER_SECRET, <<"123456">>).
-define(OAUTH_SIGNATURE_METHOD, <<"PLAINTEXT">>).
-define(ACCESS_TOKEN_URL, "https://127.0.0.1:2302/oauth/request_temp_credentials").
-define(SERVICO, <<"https://164.41.120.43:2302/netadm/info">>).


callback(Request) -> 
	Error = ems_request:get_querystring(<<"error">>, <<>>, Request),
	case Error == <<"access_denied">> of
		true ->
			{ok, Request#request{code = 401, 
				response_data = "{error: access_denied}"}
			};
		false -> 
			%Code = ems_request:get_querystring(<<"code">>, <<>>, Request),
			%Auth = base64:encode(<<?CLIENTID/binary, ":", ?SECRET/binary>>),
			%Authz = <<"Basic ", Auth/binary>>,
			%Authorization = binary:bin_to_list(Authz),
			Databin =  <<"oauth_consumer_key=", ?CONSUMER_KEY/binary, "&oauth_callback=", ?OAUTH_CALLBACK/binary,
			 "&oauth_signature_method=", ?OAUTH_SIGNATURE_METHOD/binary,"oauth_signature=">>,
			Data = binary:bin_to_list(Databin),
			case request(<<>>,Data) of
				{ok,Response} ->
					{ok, Request#request{code = 200, 
								 response_data = Response,
								 content_type = <<"application/json;charset=UTF-8">>}
				};
				{error,Error} ->
					%ResponseData = ems_schema:to_json(Error),
					{ok, Request#request{code = 401, 
								 response_data = <<"{error:", Error/binary , "}">>,
								 content_type = <<"application/json;charset=UTF-8">>}
					}
				
			end			
end.

%funções internas

acessa_servico(Token) ->
	URLbin =  <<?SERVICO/binary, "?access_token=", Token/binary>>,
	URL = binary:bin_to_list(URLbin),			
	{ok, {{_Version, 200, _ReasonPhrase}, _Headers, Net}} = 
		httpc:request(get,{URL, []}, [], []),
	Net.	

request(Authorization,Data)->
	Response = httpc:request(get,{?ACCESS_TOKEN_URL, [{"Authorization", Authorization}], "application/x-www-form-urlencoded",Data}, [], []),		
	format(Response).

format({ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}})->
	{ResponseData} = jiffy:decode(Body),
	AccessToken = proplists:get_value(<<"access_token">>,ResponseData),
    %RefreshToken = proplists:get_value(<<"reflesh_token">>, ResponseData),
	{ok, acessa_servico(AccessToken)};
	

format(_Error)-> {error, <<"access_denied">>}.




