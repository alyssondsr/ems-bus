-module(oauth2ems_client).

-export([callback/1]).
-include("../include/ems_schema.hrl").

callback(Request) -> 

	Error = ems_request:get_querystring(<<"error">>, <<>>, Request),
	case Error == <<"access_denied">> of
		true ->
			{ok, Request#request{code = 401, 
				response_data = "{error: access_denied}"}
			};
		false -> 
			Code = ems_request:get_querystring(<<"code">>, <<>>, Request),
			Client = {<<"q1w2e3">>,<<"123456">>},
			RedirectUri = <<"https://164.41.120.42:2302/callback">>,
			%io:format("\n******************************\n oauth2:authorize_code_grant(~s, ~s, ~s, <<>>),  \n******************************\n", [Client,Code,RedirectUri]),
			Authorization = oauth2:authorize_code_grant(Client, Code, RedirectUri, <<>>),
			case Authorization of 
				{ok,_} ->
					{ok,ResponseData} = issue_token_and_refresh(Authorization),
					ResponseData2 = ems_schema:prop_list_to_json(ResponseData),
					{ok, Request#request{code = 200, 
						response_data = ResponseData2}
					};
				_ ->
					%ResponseData = ems_schema:to_json(Error),
					{ok, Request#request{code = 401, 
						response_data = "{error: invalid_authz}"}
					}
			end
		end.



issue_token_and_refresh({ok, {_, Auth}}) ->
	{ok, {_, Response}} = oauth2:issue_token_and_refresh(Auth, []),
	{ok, oauth2_response:to_proplist(Response)};
issue_token_and_refresh(Error) ->
    Error.
