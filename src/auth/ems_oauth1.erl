-module(ems_oauth1).

-include("../../include/ems_config.hrl").
-include("../../include/ems_schema.hrl").

-export([serve_oauth_request_token/1]).
-export([serve_oauth_access_token/1]).
-export([serve_echo/1]).
		
-import(proplists, [get_value/2]).

serve_root(Request) ->
  case lists:member(Request:get(method), ['GET', 'HEAD']) of
    true ->
      Request:respond({303, [{"Location", "/echo"}], <<>>});
    false ->
      method_not_allowed(Request)
  end.

serve_oauth_request_token(Request = #request{type = Type, protocol_bin = Protocol, port = Port, host = Host}) ->
io:fwrite("\n aqui \n"),
  case Type of
    "GET" ->
		io:fwrite("\n GET \n"),
      serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
        case oauth:verify(Signature, "GET", URL, Params, Consumer, "") of
          true ->
            ok(Request, <<"oauth_token=requestkey&oauth_token_secret=requestsecret">>);
          false ->
            bad(Request, "invalid signature value.")
        end
      end);
    _ ->
      method_not_allowed(Request)
  end.

serve_oauth_access_token(Request) ->
io:fwrite("\n aqui \n"),

  case Request:get(method) of
    'GET' ->
      serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
        case oauth:token(Params) of
          "requestkey" ->
            case oauth:verify(Signature, "GET", URL, Params, Consumer, "requestsecret") of
              true ->
                ok(Request, <<"oauth_token=accesskey&oauth_token_secret=accesssecret">>);
              false ->
                bad(Request, "invalid signature value.")
            end;
          _ ->
            bad(Request, "invalid oauth token.")
        end
      end);
    _ ->
      method_not_allowed(Request)
  end.

serve_echo(Request) ->
  case Request:get(method) of
    'GET' ->
      serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
        case oauth:token(Params) of
          "accesskey" ->
            case oauth:verify(Signature, "GET", URL, Params, Consumer, "accesssecret") of
              true ->
                EchoParams = lists:filter(fun({K, _}) -> not lists:prefix("oauth_", K) end, Params),
                ok(Request, oauth:uri_params_encode(EchoParams));
              false ->
                bad(Request, "invalid signature value.")
            end;
          _ ->
            bad(Request, "invalid oauth token")
        end
      end);
    _ ->
      method_not_allowed(Request)
  end.

serve_oauth(Request = #request{type = Type, protocol_bin = Protocol, port = Port, host = Host}, Fun) ->
  OauthVersion    = ems_request:get_querystring(<<"oauth_version">>, <<>>, Request),
  case OauthVersion of
    "1.0" ->
      ConsumerKey = ems_request:get_querystring("oauth_consumer_key",<<>>, Request),
      SigMethod = ems_request:get_querystring("oauth_signature_method", <<>>, Request),
      case consumer_lookup(ConsumerKey, SigMethod) of
        none ->
          bad(Request, "invalid consumer (key or signature method).");
        Consumer ->
          Signature = ems_request:get_querystring("oauth_signature", <<>>, Request),
          %URL = string:concat("http://127.0.0.1:2301", Request:get(path)),
			URL = "http://127.0.0.1:2301",
          Fun(URL, proplists:delete("oauth_signature", Params), Consumer, Signature)
      end;
    _ ->
      bad(Request, "invalid oauth version.")
  end.

consumer_lookup("key", "PLAINTEXT") ->
  {"key", "secret", plaintext};
consumer_lookup("key", "HMAC-SHA1") ->
  {"key", "secret", hmac_sha1};
consumer_lookup("key", "RSA-SHA1") ->
  {"key", "data/rsa_cert.pem", rsa_sha1};
consumer_lookup(_, _) ->
  none.

ok(Request, Body) ->
			{ok, Request#request{code = 200, 
								 response_data = Body,
								 content_type = <<"application/json;charset=UTF-8">>}
			}.		
bad(Request, Reason) ->
  {ok, Request#request{code = 401, 
								 response_data = list_to_binary("Bad Request: " ++ Reason)}
	}.


method_not_allowed(Request) ->
  Request:respond({405, [], <<>>}).
