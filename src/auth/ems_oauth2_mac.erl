-module(oauth2ems_mac).

-export([issue_token/1]).
-export([verify_token/1]).
-export([start/0, stop/0]).
-include("../../include/ems_config.hrl").
-include("../../include/ems_schema.hrl").

%%%===================================================================
%%% Macros
%%%===================================================================
-define(ACCESS_TOKEN_TABLE, mac_tokens).
-define(TOKEN,   (oauth2_config:token_generation())).
-define(TABLES, [?ACCESS_TOKEN_TABLE]).
-define(TOKEN_TYPE, <<"mac">>).

%%%===================================================================
-record(a, { client   = undefined    :: undefined | term()
           , resowner = undefined    :: undefined | term()
           , scope                   :: undefined | term()
           , ttl      = 0            :: non_neg_integer()
           }).

-record(response, {
          access_token              :: oauth2:token()
          ,access_code              :: oauth2:token()
          ,expires_in               :: oauth2:lifetime()
          ,resource_owner           :: term()
          ,scope                    :: oauth2:scope()
          ,token_secret             :: oauth2:token()
          ,token_type = ?TOKEN_TYPE :: binary()
         }).

-type context()  :: proplists:proplist().
-type response() :: #response{}.
-type authz() 	 :: #a{}.
-type token()    :: oauth2:token().
-type lifetime() :: oauth2:lifetime().
-type scope()    :: oauth2:scope().

start() ->
    lists:foreach(fun(Table) ->
                          ets:new(Table, [named_table, public])
                  end,
                  ?TABLES).

stop() ->
    lists:foreach(fun ets:delete/1, ?TABLES).

issue_token(Authz = #a{client=Client, resowner=Owner, scope=Scope, ttl=TTL}) ->
    Secret  = ?TOKEN:generate(Client),
    Context = build_context(Client,seconds_since_epoch(TTL),Owner,Scope, Secret),
    AccessToken  = ?TOKEN:generate(Context),
    put(?ACCESS_TOKEN_TABLE,AccessToken,Context),
    Response = response(AccessToken, Secret, Authz),
    {ok, {AccessToken, Response}}.

%%%===================================================================
%%% Resolve Token
%%%===================================================================
verify_token(Request) ->
    serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
	    Token = ems_request:get_querystring(<<"oauth_token">>, [],Request),
	    Nonce = ems_request:get_querystring(<<"nonce">>, [],Request),
	    case resolve_token(Token) of
			{ok,{_,GrantCtx}} ->
				OauthNonce = get_(GrantCtx,<<"oauth_nonce">>),
				case OauthNonce == Nonce of	
				true -> 	{"error: invalid nonce."};
				false -> 	
					associate_nonce(Token, Nonce, GrantCtx),
					{ok,RequestSecret} = get_(GrantCtx,<<"token_secret">>),
					case oauth:verify(binary:bin_to_list(Signature), "POST", URL, maps:to_list(Params), Consumer, binary:bin_to_list(RequestSecret)) of
						true -> ok;
						false ->{"error: invalid signature value."}
					end
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
		case authenticate_client(ConsumerKey, SigMethod) of
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
authenticate_client(ClientId, _Method) ->
    case ems_client:find_by_codigo(ClientId) of
			{ok, _Client} ->	  {ClientId, "secret", hmac_sha1};
			_ -> {error, unauthorized_client}		
    end.

resolve_token(AccessToken) ->
    case get(?ACCESS_TOKEN_TABLE,AccessToken) of
       {ok,Value} -> {ok,{[],Value}};
        _Error -> {error, invalid_token} 
    end.

associate_nonce(Token, Nonce, GrantCtx) ->
	Consumer = get_(GrantCtx,<<"consumer">>),
	RequestSecret = get_(GrantCtx,<<"oauth_token_secret">>),
	Callback = get_(GrantCtx,<<"oauth_callback">>),
	Verifier = get_(GrantCtx,<<"oauth_verifier">>),
	Context = build_context(Consumer, RequestSecret, Callback, Verifier,Nonce),							
	update(?ACCESS_TOKEN_TABLE, Token, Context),
	{ok}.

-spec build_context(term(), lifetime(), term(), scope(), term()) -> context().
build_context(Client, ExpiryTime, ResOwner, Scope, Secret) ->
    [ {<<"client">>,         Client}
    , {<<"resource_owner">>, ResOwner}
    , {<<"expiry_time">>,    ExpiryTime}
    , {<<"scope">>,          Scope}
    , {<<"nonce">>,          <<>>}
    , {<<"token_secret">>,   Secret} ].
    
-spec response(token(), token(), authz()) -> response().
response(AccessToken,TokenSecret, #a{resowner=ResOwner, scope=Scope, ttl=ExpiresIn}) ->
    Response = #response{ access_token             = AccessToken
						, expires_in               = ExpiresIn
						, resource_owner           = ResOwner
						, scope                    = Scope
						, token_secret             = TokenSecret
				},
             to_proplist(Response).

-spec seconds_since_epoch(integer()) -> non_neg_integer().
seconds_since_epoch(Diff) ->
    {Mega, Secs, _} = os:timestamp(),
    Mega * 1000000 + Secs + Diff.
    
-spec to_proplist(response()) -> proplists:proplist().
to_proplist(Response) ->
    response_foldr(Response, fun(Key, Value, Acc) -> [{Key, Value} | Acc] end, []).
-spec response_foldr(Response, Fun, Acc0) -> Return when
    Response :: response(),
    Fun      :: fun((Key::binary(), Value::any(), Acc::any()) -> Acc::any()),
    Acc0     :: any(),
    Return   :: any().
response_foldr(Record, Fun, Acc0) ->
    Keys = record_info(fields, response),
    Values = tl(tuple_to_list(Record)), %% Head is 'response'!
    response_foldr(Keys, Values, Fun, Acc0).

response_foldr([], [], _Fun, Acc0) ->
    Acc0;
response_foldr([_ | Ks], [undefined | Vs], Fun, Acc) ->
    response_foldr(Ks, Vs, Fun, Acc);
response_foldr([refresh_token_expires_in | Ks], [V | Vs], Fun, Acc) ->
    Fun(<<"refresh_token_expires_in">>, V, response_foldr(Ks, Vs, Fun, Acc));
response_foldr([expires_in | Ks], [V | Vs], Fun, Acc) ->
    Fun(<<"expires_in">>, V, response_foldr(Ks, Vs, Fun, Acc));
response_foldr([K | Ks], [V | Vs], Fun, Acc) ->
    Key = atom_to_binary(K, latin1),
    %Value = to_binary(V),
    Fun(Key, V, response_foldr(Ks, Vs, Fun, Acc)).
 
get(O, K, _)  ->
    case lists:keyfind(K, 1, O) of
        {K, V} -> {ok, V};
        false  -> {error, notfound}
    end.
      
get(Table, Key) ->
    case ets:lookup(Table, Key) of
        [] ->
            {error, notfound};
        [{_Key, Value}] ->
            {ok, Value}
    end.
get_(O, K) ->
    V = get(O, K, <<>>),
    V.

       
put(Table, Key, Value) ->
    ets:insert(Table, {Key, Value}),
    ok.

bad(Request, Reason) ->
	{ok, Request#request{code = 401, 
								 response_data = list_to_binary("Bad Request: " ++ Reason)}
	}.
update(Table, Key, Value) ->
	ets:update_element(Table,Key,{2,Value}).



