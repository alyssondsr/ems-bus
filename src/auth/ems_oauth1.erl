-module(ems_oauth1).

-include("../../include/ems_config.hrl").
-include("../../include/ems_schema.hrl").
-export([start/0, stop/0]).
-export([serve_oauth_request_token/1]).
-export([serve_oauth_access_token/1]).
-export([verify_token/1]).
-export([oauth_ro_authz/1]).
-export([issue_token/3]).

-import(proplists, [get_value/2]).

-define(ACCESS_TOKEN_TABLE, access_tokens1).
-define(TMP_TOKEN_TABLE, tmp_tokens).
-define(TOKEN_TABLE, cli_tokens).

-define(TABLES, 	[?ACCESS_TOKEN_TABLE,
					?TOKEN_TABLE,
					?TMP_TOKEN_TABLE]).

start() ->
    lists:foreach(fun(Table) ->
                          ets:new(Table, [named_table, public])
                  end,
                  ?TABLES).

stop() ->
    lists:foreach(fun ets:delete/1, ?TABLES).


serve_oauth_request_token(Request = #request{type = Type}) ->
	serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
	case oauth:verify(binary:bin_to_list(Signature), Type, URL, maps:to_list(Params), Consumer, <<>>) of
		true ->
			RequestToken  = oauth2_token:generate(<<>>),
			RequestSecret  = oauth2_token:generate(<<>>),
			Callback = ems_request:get_querystring(<<"oauth_callback">>, [],Request),
			issue_token(RequestToken,RequestSecret,Consumer,Callback),
			ok(Request, <<"oauth_token=",RequestToken/binary,"&oauth_token_secret=",RequestSecret/binary>>);
		false ->
			bad(Request, "invalid signature value.")
		end
	end).

oauth_ro_authz(Request = #request{authorization = Authorization}) ->
	case ems_http_util:parse_basic_authorization_header(Authorization) of
		{ok, Login, Password} ->
			case ems_user:authenticate_login_password(Login, list_to_binary(Password)) of
				ok ->
				    RequestToken = ems_request:get_querystring(<<"oauth_token">>, [],Request),
				    case resolve_token(?TMP_TOKEN_TABLE,RequestToken) of
						{ok, {_, GrantCtx}} ->
							Verifier  = oauth2_token:generate(<<>>),
							{ok, Callback} = associate_verifier(RequestToken, Verifier, GrantCtx),
							Path = <<"oauth_token=",RequestToken/binary,"&oauth_verifier=",Verifier/binary>>,
							redirect(Request, Callback, Path);							
						{error, _} -> bad(Request, "invalid token.")
					end;
				_ -> bad(Request, "invalid user.")
			end;
		_Error -> bad(Request, "invalid authz.")
	end.

serve_oauth_access_token(Request) ->
	serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
		RequestToken = ems_request:get_querystring(<<"oauth_token">>, [],Request),
		case resolve_token(?TMP_TOKEN_TABLE,RequestToken) of
			{ok,{_,GrantCtx}} ->
				RequestSecret = get_(GrantCtx,<<"oauth_token_secret">>),
				case oauth:verify(binary:bin_to_list(Signature), "POST", URL, maps:to_list(Params), Consumer, binary:bin_to_list(RequestSecret)) of
					true ->
						Token  = oauth2_token:generate(<<>>),
						Secret  = oauth2_token:generate(<<>>),
						issue_token(Token,Secret,Consumer),
						ok(Request,  <<"oauth_token=",Token/binary,"&oauth_token_secret=",Secret/binary>>);
					false ->
						bad(Request, "invalid signature value.")
					end;
				_ -> bad(Request, "invalid token.")
        end
      end).
      
verify_token(Request) ->
    serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
	    Token = ems_request:get_querystring(<<"oauth_token">>, [],Request),
		io:format("\n Token = ~s e Token = ~s \n",[Token,Token]),
	    case resolve_token(?ACCESS_TOKEN_TABLE,Token) of
			{ok,{_,GrantCtx}} ->
				RequestSecret = get_(GrantCtx,<<"oauth_token_secret">>),
				case oauth:verify(binary:bin_to_list(Signature), "POST", URL, maps:to_list(Params), Consumer, binary:bin_to_list(RequestSecret)) of
					true -> ok;
					false ->{"error: invalid signature value."}
				end;
			_ -> {"error: invalid token."}
		end
	end).

serve_oauth(Request = #request{uri = URL}, Fun) ->
	Params = Request#request.querystring_map,
	case maps:get(<<"oauth_version">>, Params) of
		<<"1.0">> ->
			ConsumerKey = maps:get(<<"oauth_consumer_key">>, Params),
			SigMethod = maps:get(<<"oauth_signature_method">>, Params),
		case consumer_lookup(ConsumerKey, SigMethod) of
			none ->	bad(Request, "invalid consumer (key or signature method).");
			Consumer ->
				Signature = maps:get(<<"oauth_signature">>, Params),
				Fun(binary:bin_to_list(URL), maps:remove(<<"oauth_signature">>, Params), Consumer, Signature)
		end;
		_ -> bad(Request, "invalid oauth version.")
  end.

%%%===================================================================
%%% Funções internas
%%%===================================================================

issue_token(AccessToken, Secret, Consumer, Callback) ->
	Context = build_context(Consumer, Secret, Callback, <<>>),
    {put(?TMP_TOKEN_TABLE,AccessToken,Context)}.

issue_token(AccessToken, Secret, Consumer) ->
	Context = build_context(Consumer, Secret,<<>>,<<>>),
    {put(?ACCESS_TOKEN_TABLE,AccessToken,Context)}.
    
associate_verifier(RequestToken, Verifier, GrantCtx) ->
	Consumer = get_(GrantCtx,<<"consumer">>),
	RequestSecret = get_(GrantCtx,<<"oauth_token_secret">>),
	Callback = get_(GrantCtx,<<"oauth_callback">>),
	Context = build_context(Consumer, RequestSecret, Callback, Verifier),							
	update(?TMP_TOKEN_TABLE, RequestToken, Context),
	{ok, Callback}.

resolve_token(Table,AccessToken) ->
    case get(Table, AccessToken) of
       {ok,Value} -> {ok,{[],Value}};
        _Error -> {error, invalid_token} 
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
redirect(Request, RedirectUri, Path) ->
	LocationPath = <<RedirectUri/binary,"?",Path/binary>>,
	{ok, Request#request{code = 302, 
		 response_data = <<"{}">>,
		 response_header = #{
					<<"location">> => LocationPath
					}
		}
	}.
  
build_context(Consumer, RequestSecret, Callback, Verifier) ->
    [ {<<"consumer">>,  Consumer}
    , {<<"oauth_verifier">>,  Verifier}
    , {<<"oauth_callback">>,  Callback}
    , {<<"oauth_token_secret">>, RequestSecret}].

get(Table, Key) ->
    case ets:lookup(Table, Key) of
        [] ->
            {error, notfound};
        [{_Key, Value}] ->
            {ok, Value}
    end.
get(O, K, _)  ->
    case lists:keyfind(K, 1, O) of
        {K, V} -> {ok, V};
        false  -> {error, notfound}
    end.

get_(O, K) ->
    {ok, V} = get(O, K, []),
    V.


put(Table, Key, Value) ->
    ets:insert(Table, {Key, Value}),
    ok.
update(Table, Key, Value) ->
	ets:update_element(Table,Key,{2,Value}).
	
del(Table, Key) ->
    ets:delete(Table, Key).

