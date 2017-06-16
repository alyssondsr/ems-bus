-module(ems_oauth1).

-include("../../include/ems_config.hrl").
-include("../../include/ems_schema.hrl").

-export([serve_oauth_request_token/1]).
-export([serve_oauth_access_token/1]).
-export([serve_echo/1]).
		
-import(proplists, [get_value/2]).

serve_oauth_request_token(Request = #request{type = Type}) ->
  case Type of
    "GET" ->
      serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
        case oauth:verify(binary:bin_to_list(Signature), "GET", URL, maps:to_list(Params), Consumer, <<>>) of
          true ->
            ok(Request, <<"oauth_token=requestkey&oauth_token_secret=requestsecret">>);
          false ->
            bad(Request, "invalid signature value.")
        end
      end);
    _ ->
      method_not_allowed(Request)
  end.

serve_oauth_access_token(Request = #request{type = Type}) ->
  case Type of
    "GET" ->
      serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
		case oauth:token(maps:to_list(Params)) of
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

serve_echo(Request = #request{type = Type}) ->
  case Type of
    "GET" ->
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

serve_oauth(Request, Fun) ->
  Params = Request#request.querystring_map,
  %io:format("\n map: ~s\n",[erlang:map_size(Params)]),
  %io:format("\n map: ~s\n",[Params]),
  case maps:get(<<"oauth_version">>, Params) of
    <<"1.0">> ->
      ConsumerKey = maps:get(<<"oauth_consumer_key">>, Params),
      SigMethod = maps:get(<<"oauth_signature_method">>, Params),
      case consumer_lookup(ConsumerKey, SigMethod) of
        none ->
          bad(Request, "invalid consumer (key or signature method).");
        Consumer ->
          io:format("\n aqui:  \n"),
          Signature = maps:get(<<"oauth_signature">>, Params),
          io:format("\n Signature: ~p \n",[Signature]),
          URL = "http://127.0.0.1:2301", 
          io:format("\n URL: ~p \n",[URL]),
          Fun(URL, maps:remove(<<"oauth_signature">>, Params), Consumer, Signature)
      end;
    _ ->
      bad(Request, "invalid oauth version.")
  end.

consumer_lookup(<<"key">>, <<"PLAINTEXT">>) ->
  {"key", "secret", plaintext};
consumer_lookup(<<"key">>, <<"HMAC-SHA1">>) ->
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
