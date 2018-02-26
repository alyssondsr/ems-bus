-module(ems_oauth2_backend).

-behavior(oauth2_backend).

-include("../../include/ems_config.hrl").
-include("../../include/ems_schema.hrl").

%%% API
-export([start/0, stop/0]).

-export([authenticate_user/2]).
-export([authenticate_client/2]).
-export([authorize_refresh_token/3]).
-export([get_client_identity/2]).
-export([associate_access_code/3]).
-export([associate_refresh_token/3]).
-export([associate_access_token/3]).
-export([resolve_access_code/2]).
-export([resolve_refresh_token/2]).
-export([resolve_access_token/2]).
-export([revoke_access_code/2]).
-export([revoke_access_token/2]).
-export([revoke_refresh_token/2]).
-export([get_redirection_uri/2]).
-export([verify_redirection_uri/3]).
-export([verify_client_scope/3]).
-export([verify_resowner_scope/3]).
-export([verify_scope/3]).

-define(ACCESS_TOKEN_TABLE, access_tokens).
-define(ACCESS_CODE_TABLE, access_codes).
-define(REFRESH_TOKEN_TABLE, refresh_tokens).
-define(SCOPE_TABLE, scopes).


-define(TABLES, [?ACCESS_TOKEN_TABLE,
				 ?ACCESS_CODE_TABLE,
                 ?REFRESH_TOKEN_TABLE]).

% verificar: unificar os dois records ... %%%%%%%%%%%%%%%
         
-record(a, { client   = undefined    :: undefined | term()
           , resowner = undefined    :: undefined | term()
           , scope                   :: oauth2:scope()
           , ttl      = 0            :: non_neg_integer()
           }).

%%%===================================================================
%%% 
%%%===================================================================

start() ->
    application:set_env(oauth2, backend, oauth2ems_backend),
    ems_user:insert(#user{login= <<"geral">>,password= ems_util:criptografia_sha1("123456")}),
    ems_user:insert(#user{login= <<"alyssondsr">>,password=ems_util:criptografia_sha1("123456")}),
    ems_client:insert(#client{name= <<"123">>,secret=ems_util:criptografia_sha1("123456"), redirect_uri= <<"http://127.0.0.1:2301/callback">>, scope= <<"email">>}),
    ems_client:insert(#client{name= <<"q1w2e3">>,secret=ems_util:criptografia_sha1("123456"), redirect_uri= <<"https://164.41.120.43:2344/callback">>, scope= <<"email">>}),
    ems_client:insert(#client{name= <<"key">>,secret=ems_util:criptografia_sha1("secret"), redirect_uri= <<"https://127.0.0.1:2344/callback1">>, scope= <<"email">>}),
    ems_client:insert(#client{name= <<"teste">>,secret=ems_util:criptografia_sha1("123456"), redirect_uri= <<"https://164.41.120.34:2344/callback">>, scope= <<"email">>}),
    ems_client:insert(#client{name= <<"98755">>,secret=ems_util:criptografia_sha1("123456"), redirect_uri= <<"https://www.getpostman.com/oauth2/callback">>, scope= <<"email">>}),

    lists:foreach(fun(Table) ->
			ets:new(Table, [named_table, public])
		end,
    ?TABLES).

stop() ->
    lists:foreach(fun ets:delete/1, ?TABLES).
    


%%%===================================================================
%%% OAuth2 backend functions
%%%===================================================================

authenticate_user({Login, Password}, _) ->
%<<<<<<< HEAD
%<<<<<<< HEAD
 %   case ems_user:authenticate_login_password(Login, Password) of
%		ok ->	{ok, {<<>>,Login}};
%=======
%    case ems_user:find_by_login_and_password(Login, Password) of
%		{ok, #user{id = Id, user_id = UserId, matricula = Matricula, name = Name, email = Email, type = Type, lotacao = Lotacao}} ->	
%			ResourceOwner = [{<<"id">>, Id,
%							  <<"login">>, Login, 
%							  <<"user_id">>, UserId,
%							  <<"name">>, Name,
%							  <<"matricula">>, Matricula,
%							  <<"email">>, Email,
%							  <<"type">>, Type,
%							  <<"lotacao">>, Lotacao}],
%			{ok, {<<>>, ResourceOwner}};
%>>>>>>> upstream/master
%=======
    case ems_user:find_by_login_and_password(Login, Password) of
		{ok, User} -> 
				io:format("\n\n\n Res = ~p \n\n\n",[ems_user:to_resource_owner(User)]),
				{ok, {<<>>, {Login, <<"passwd">>}}};
%>>>>>>> upstream/master
		_ -> {error, unauthorized_user}
	end.
	
authenticate_client({ClientId, Secret},_) ->
    case ems_client:find_by_id_and_secret(ClientId, Secret) of
		{ok, Client} ->	 {ok, {<<>>, Client}};
		_ -> {error, unauthorized_client}		
    end.
    
get_client_identity(ClientId, _) ->
    case ems_client:find_by_id(ClientId) of
        {ok, Client} -> {ok, {[], Client}};
        _ -> {error, unauthorized_client}
    end.
        

associate_access_code(AccessCode, Context, _AppContext) ->
    {put(?ACCESS_CODE_TABLE, AccessCode, Context), Context}.

associate_refresh_token(RefreshToken, Context, _) ->
    {put(?REFRESH_TOKEN_TABLE, RefreshToken, Context), Context}.

associate_access_token(AccessToken, Context, _) ->
    {put(?ACCESS_TOKEN_TABLE, AccessToken, Context), Context}.

resolve_access_code(AccessCode, _) ->
	case get(?ACCESS_CODE_TABLE, AccessCode) of
        {ok,Value} -> 	{ok,{[],Value}};
        _Error -> {error, invalid_code} 
    end.

resolve_refresh_token(RefreshToken, _AppContext) ->
    case get(?REFRESH_TOKEN_TABLE, RefreshToken) of
       {ok,Value} -> {ok,{[], Value}};
        _Error -> {error, invalid_token} 
    end.

resolve_access_token(AccessToken, _) ->
    case get(?ACCESS_TOKEN_TABLE, AccessToken) of
       {ok,Value} -> {ok,{[], Value}};
        _Error -> {error, invalid_token} 
    end.

revoke_access_code(AccessCode, _AppContext) ->
    %delete(?ACCESS_CODE_TABLE, AccessCode),
    {ok, []}.

revoke_access_token(AccessToken, _) ->
    delete(?ACCESS_TOKEN_TABLE, AccessToken),
    {ok, []}.

revoke_refresh_token(_RefreshToken, _) ->
    {ok, []}.

get_redirection_uri(ClientId, _) ->
    case get_client_identity(ClientId, [])  of
        {ok, #client{redirect_uri = RedirectUri}} -> {ok, RedirectUri};
        _ -> {error, einvalid_uri} 
    end.


verify_redirection_uri(#client{redirect_uri = RedirUri}, ClientUri, _) ->
    case ClientUri =:= RedirUri of
		true -> 
			{ok, []};
		_Error -> 
			{error, unauthorized_client}
    end;
verify_redirection_uri(ClientId, ClientUri, _) ->
    case get_client_identity(ClientId, []) of
        {ok, {_, #client{redirect_uri = RedirUri}}} -> 
			case ClientUri =:= RedirUri of
				true ->	{ok, []};
				_ -> {error, unauthorized_client}
			end;
        Error -> Error
    end;

verify_redirection_uri(#client{redirect_uri = RedirUri}, ClientUri, _) ->
    case ClientUri =:= RedirUri of
		true -> {ok,[]};
		_Error -> {error, error_uri}
    end.

verify_client_scope(#client{id = ClientID}, Scope, _) ->
	case ems_client:find_by_id(ClientID) of
        {ok, #client{scope = Scope0}} ->     
			case Scope =:= Scope0 of
				true -> 
					{ok, {[],Scope0}};
				_ -> {error, unauthorized_client}
			end;
        _ -> {error, invalid_scope}
    end.
verify_resowner_scope(_ResOwner, Scope, _) ->
    {ok, {[], Scope}}.

verify_scope(_RegScope, Scope , _) ->
    {ok, {[], Scope}}.

    
% função criada pois a biblioteca OAuth2 não trata refresh_tokens

authorize_refresh_token(Client, RefreshToken, Scope) ->
    case authenticate_client(Client, []) of
        {error, _}      -> {error, invalid_client};
        {ok, {_, C}} -> 
			case resolve_refresh_token(RefreshToken, []) of
				{error, _} = E           -> E;
				{ok, {_, GrantCtx}} -> 
					case verify_client_scope(C, Scope, []) of
						{error, _}           -> {error, invalid_scope};
						{ok, {Ctx3, _}} ->
							{ok, {Ctx3, #a{ client  =C
								, resowner= get_(GrantCtx,<<"resource_owner">>)
								, scope   = get_(GrantCtx, <<"scope">>)
								, ttl     = oauth2_config:expiry_time(password_credentials)
							}}}
					end
            end
    end.



%%%===================================================================
%%% Funções internas
%%%===================================================================

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

delete(Table, Key) ->
    ets:delete(Table, Key).
    
