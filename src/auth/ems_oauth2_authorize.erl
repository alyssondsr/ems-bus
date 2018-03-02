-module(ems_oauth2_authorize).

-export([execute/1]).
-export([code_request/1]).
-export([implicit_token_request/1]).
-export([authn_user/1]).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").



execute(Request = #request{type = Type, 
						   protocol_bin = Protocol, 
						   port = Port, 
						   host = Host
						   %service  = #service{oauth2_allow_client_credentials = OAuth2AllowClientCredentials}
						   }) -> 
	try
		case Type of
			<<"GET">> -> GrantType = ems_util:get_querystring(<<"response_type">>, <<>>, Request);
			<<"POST">> -> GrantType = ems_util:get_querystring(<<"grant_type">>, <<>>, Request);
			_ -> GrantType = undefined
		end,
	    io:format("\n\n\n GrantType = ~s \n\n\n",[GrantType]),

		Result = case GrantType of
		<<"password">> -> 
			ems_db:inc_counter(ems_oauth2_grant_type_password),
			password_grant(Request);
		<<"client_credentials">> ->	
			%case OAuth2AllowClientCredentials of
			%	true ->
					ems_db:inc_counter(ems_oauth2_grant_type_client_credentials),
					client_credentials_grant(Request);
			%	false ->
			%					    io:format("\n\n\n OAuth2AllowClientCredentials = ~s \n\n\n",[OAuth2AllowClientCredentials]),

			%		ems_db:inc_counter(ems_oauth2_client_credentials_denied),
			%		{error, access_denied}	
			%	end;
		<<"token">> -> 
			ems_db:inc_counter(ems_oauth2_grant_type_token),
			authorization_request(Request);
		<<"code">> ->	
			%ems_db:inc_counter(ems_oauth2_grant_type_code),
			authorization_request(Request);	
		<<"authorization_code">> ->	
			ems_db:inc_counter(ems_oauth2_grant_type_authorization_code),
			access_token_request(Request,GrantType);
		<<"mac">> ->		access_token_request(Request,GrantType);
		<<"refresh_token">> ->	
			ems_db:inc_counter(ems_oauth2_grant_type_refresh_token),
			refresh_token_request(Request);	
		_ -> {error, invalid_oauth2_grant}
	end,  
	case Result of
		{ok, ResponseData} -> 	
			ok(Request, ResponseData);		
		{redirect, Data} -> 
			LocationPath = iolist_to_binary([Protocol,<<"://"/utf8>>, Host, <<":"/utf8>>,list_to_binary(integer_to_list(Port)),Data]),
			redirect(Request, LocationPath);			
		Error ->	bad(401, Request, Error)
	end
	catch
		_:_ -> 		bad(500, Request, {error, internal_error})
	end.
	
%% Requisita o código de autorização - seções 4.1.1 e 4.1.2 do RFC 6749.
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code2&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w
code_request(Request = #request{authorization = Authorization}) ->
	try
		ClientId    = ems_util:get_querystring(<<"client_id">>, [],Request),
		RedirectUri = ems_util:get_querystring(<<"redirect_uri">>, [],Request),
		State      = ems_util:get_querystring(<<"state">>, [],Request),
		Scope       = ems_util:get_querystring(<<"scope">>, [],Request),
		Username = ems_util:get_querystring(<<"username">>, <<>>, Request),
		Password = ems_util:get_querystring(<<"password">>, <<>>, Request),
	    case credential_extract({Username,Password},Authorization) of
			{ok,{User,Passwd}} -> 
		    Authz = oauth2:authorize_code_request({User,Passwd}, ClientId, RedirectUri, Scope, []),
			case issue_code(Authz) of
					{ok, Response} ->
						Code = element(2,lists:nth(1,Response)),
						LocationPath = <<RedirectUri/binary,"?code=", Code/binary,"&state=",State/binary>>,
						redirect(Request, LocationPath);
					_ ->
						LocationPath = <<RedirectUri/binary,"?error=access_denied&state=",State/binary>>,
						redirect(Request, LocationPath)
					end;
			Error -> bad(401,Request, Error)
		end
		catch
			_:_ -> bad(500,Request, <<>>)
		end.
	
authn_user(Request = #request{authorization = Authorization}) ->
	case ems_http_util:parse_basic_authorization_header(Authorization) of
		{ok, Login, Password} ->
			case ems_user:authenticate_login_password(list_to_binary(Login), list_to_binary(Password)) of
					ok ->	ok(Request, <<"{}">>);
					_ -> {error, unauthorized_user}
			end;
		Error -> Error
	end.	


implicit_token_request(Request = #request{authorization = Authorization}) ->
    ClientId    = ems_util:get_querystring(<<"client_id">>, [],Request),
    RedirectUri = ems_util:get_querystring(<<"redirect_uri">>, [],Request),
    State      = ems_util:get_querystring(<<"state">>, [],Request),
    Scope       = ems_util:get_querystring(<<"scope">>, [],Request),
    case ems_http_util:parse_basic_authorization_header(Authorization) of
		{ok, Username, Password} ->
		    Authz = oauth2:authorize_code_request({Username,list_to_binary(Password)}, ClientId, RedirectUri, Scope, []),
			case issue_token(Authz) of
				{ok, Response} ->
					Token = element(2,lists:nth(1,Response)),
					Ttl = element(4,lists:nth(1,Response)),
					Type = element(10,lists:nth(1,Response)),
					LocationPath = <<RedirectUri/binary,"?token=", Token/binary,"&state=",State/binary,"&token_type=",Type/binary,"&expires_in=",Ttl/binary>>,
					redirect(Request, LocationPath);
				_ ->
					LocationPath = <<RedirectUri/binary,"?error=access_denied&state=",State/binary>>,
					redirect(Request, LocationPath)
				end;
			
		_ ->
			LocationPath = <<RedirectUri/binary,"?error=access_denied&state=",State/binary>>,
			redirect(Request, LocationPath)
		end.


	
%%%===================================================================
%%% Funções internas
%%%===================================================================


%% Cliente Credencial Grant- seção 4.4.1 do RFC 6749. 
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=client_credentials&client_id=s6BhdRkqt3&secret=qwer
client_credentials_grant(Request = #request{authorization = Authorization}) ->
	try
		ClientId = ems_util:get_querystring(<<"client_id">>, <<>>,Request),
		Scope = ems_util:get_querystring(<<"scope">>, <<>>, Request),
		Secret = ems_util:get_querystring(<<"client_secret">>, <<>>, Request),
		% O ClientId também pode ser passado via header Authorization
		case credential_extract({ClientId,Secret},Authorization) of
			{ok,{Id,ClientSecret}} -> 
			    %io:format("\n\n\n ClientId = ~s \n\n\n",[Id]),
			    %io:format("parse_client_id = ~4..0B~n \n",[parse_client_id(Id)]),
				Auth = oauth2:authorize_client_credentials({parse_client_id(Id),ClientSecret}, Scope, []),
				issue_token(Auth);
			_Error -> {error, invalid_client_credentials}
		end
	catch
		_:_ -> bad(500, Request, {error, internal_error})
	end.
	
%% Resource Owner Password Credentials Grant - seção 4.3.1 do RFC 6749.
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=password&username=johndoe&password=A3ddj3w
password_grant(Request = #request{authorization = Authorization}) ->
	try
		Username = ems_util:get_querystring(<<"username">>, <<>>, Request),
		Password = ems_util:get_querystring(<<"password">>, <<>>, Request),
		Scope = ems_util:get_querystring(<<"scope">>, <<>>, Request),
	    case credential_extract({Username,Password},Authorization) of
			{ok,{User,Pass}} ->
				Authz = oauth2:authorize_password({User,Pass}, Scope, []),
				issue_token(Authz);
			Error -> Error
		end
	catch
		_:_ -> bad(500, Request, {error, internal_error})
	end.	
	
%% Verifica a URI do Cliente e redireciona para a página de autorização - Implicit Grant e Authorization Code Grant
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html   
authorization_request(Request = #request{authorization = _Authorization}) ->
	ClientId = ems_util:get_querystring(<<"client_id">>, <<>>,Request),
    RedirectUri = ems_util:get_querystring(<<"redirect_uri">>, <<>>, Request),
    State = ems_util:get_querystring(<<"state">>, <<>>, Request),
    Scope = ems_util:get_querystring(<<"scope">>, <<>>, Request),
    Resposta = case oauth2ems_backend:verify_redirection_uri(ClientId, RedirectUri, []) of
		{ok,_} ->
			Data = <<"/login/index.html?response_type=code&client_id=", ClientId/binary,"&redirect_uri=", RedirectUri/binary,"&state=",State/binary,"&scope=",Scope/binary>>,
		    io:format("\n\n\n Data = ~s \n\n\n",[Data]),
			{redirect, Data};
		Error -> 	Error
	end,
    Resposta.

%% Requisita o código de autorização - seções 4.1.1 e 4.1.2 do RFC 6749.
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code2&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w
refresh_token_request(Request) ->
    ClientId    = ems_util:get_querystring(<<"client_id">>, [],Request),
    ClientSecret = ems_util:get_querystring(<<"client_secret">>, [],Request),
	Reflesh_token = ems_util:get_querystring(<<"refresh_token">>, [],Request),
	Scope    = ems_util:get_querystring(<<"scope">>, [],Request),
	Authorization = oauth2ems_backend:authorize_refresh_token({ClientId, ClientSecret},Reflesh_token,Scope),
    issue_token(Authorization).  

%% Requisita o token de acesso com o código de autorização - seções  4.1.3. e  4.1.4 do RFC 6749.
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=authorization_code&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w&secret=qwer&code=dxUlCWj2JYxnGp59nthGfXFFtn3hJTqx
access_token_request(Request = #request{authorization = Authorization},GrantType) ->
	Code = ems_util:get_querystring(<<"code">>, [],Request),
	ClientId    = ems_util:get_querystring(<<"client_id">>, [],Request),
    RedirectUri = ems_util:get_querystring(<<"redirect_uri">>, [],Request),
    ClientSecret = ems_util:get_querystring(<<"client_secret">>, [],Request),
    case credential_extract({ClientId,ClientSecret},Authorization) of
		{ok,{ClientId2,Secret}} -> 
			Auth = oauth2:authorize_code_grant({ClientId2, Secret}, Code, RedirectUri, []),
			case GrantType of
				<<"mac">> -> issue_mac_token(Auth);
				<<"authorization_code">> -> issue_token_and_refresh(Auth)
			end;						
		_Error -> {error, invalid_client}					
	end.  

credential_extract({User, Pass}, Authorization) ->
	case User == <<>> of
		true -> 
			case Authorization =/= undefined of
				true ->
					case ems_util:parse_basic_authorization_header(Authorization) of
						{ok, Login, Password} ->
							{ok,{list_to_binary(Login), list_to_binary(Password)}};
						Error -> Error
					end;
				false -> {error, invalid_credentials}
			end;
		false -> 
			{ok,{User, Pass}}
end.



%issue_token({ok, {_, Auth}}) ->
	%io:format("\n\n\n ++++++++++ issue_token *********************\n\n\n"),
	%{ok, {_, Response}} = oauth2:issue_token(Auth, []),
	%{ok, oauth2_response:to_proplist(Response)};
%issue_token(Error) ->
    %Error.
    

%issue_token_and_refresh({ok, {_, Auth}}) ->
	%{ok, {_, Response}} = oauth2:issue_token_and_refresh(Auth, []),
	%{ok, oauth2_response:to_proplist(Response)};
%issue_token_and_refresh(Error) ->
    %Error.			

issue_token({ok, {_, Auth}}) ->
	{ok, {_, {response, AccessToken, 
						undefined,
						ExpiresIn,
						User,
						Scope, 
						RefreshToken, 
						RefreshTokenExpiresIn,
						TokenType
             }
		}} = oauth2:issue_token(Auth, []),
	{ok, [{<<"access_token">>, AccessToken},
            {<<"expires_in">>, ExpiresIn},
            {<<"resource_owner">>, User},
            {<<"scope">>, Scope},
            {<<"refresh_token">>, RefreshToken},
            {<<"refresh_token_expires_in">>, RefreshTokenExpiresIn},
            {<<"token_type">>, TokenType}]};
issue_token(_) -> {error, access_denied}.
    

issue_token_and_refresh({ok, {_, Auth}}) ->
	{ok, {_, {response, AccessToken, 
						undefined,
						ExpiresIn,
						User,
						Scope, 
						RefreshToken, 
						RefreshTokenExpiresIn,
						TokenType
             }
		}} = oauth2:issue_token_and_refresh(Auth, []),
	{ok, [{<<"access_token">>, AccessToken},
            {<<"expires_in">>, ExpiresIn},
            {<<"resource_owner">>, User},
            {<<"scope">>, Scope},
            {<<"refresh_token">>, RefreshToken},
            {<<"refresh_token_expires_in">>, RefreshTokenExpiresIn},
            {<<"token_type">>, TokenType}]};
issue_token_and_refresh(_) -> 
	{error, access_denied}.
%>>>>>>> upstream/master

issue_code({ok, {_, Auth}}) ->
	{ok, {_, Response}} = oauth2:issue_code(Auth, []),
	{ok, oauth2_response:to_proplist(Response)};
issue_code(Error) ->
    Error.
    
issue_mac_token({ok, {_, Auth}}) ->
	{ok, {_Token, Response}} = oauth2ems_mac:issue_token(Auth),
	{ok, Response};
issue_mac_token(Error) ->
    Error.

ok(Request, Body) when is_list(Body) ->
	{ok, Request#request{code = 200, 
		response_data = ems_schema:prop_list_to_json(Body),
		content_type_out = <<"application/json;charset=UTF-8">>}
	};
ok(Request, Body) ->
	{ok, Request#request{code = 200, 
		response_data = Body,
		content_type_out = <<"application/json;charset=UTF-8">>}
	}.		
		
bad(Code, Request, {_,Reason}) ->
	ResponseData = ems_schema:to_json({error,Reason}),
	{ok, Request#request{code = Code,
		reason = Reason,
		response_data = ResponseData}
	}.
redirect(Request, LocationPath) ->
	{ok, Request#request{code = 302, 
		 response_data = <<"{}">>,
		 response_header = #{
					<<"location">> => LocationPath
					}
		}
	}.

-spec parse_client_id(binary()) -> non_neg_integer().
parse_client_id(<<>>) -> 0;
parse_client_id(Value) -> 
	try
		erlang:binary_to_integer(Value)
	catch
		_:_ -> 0
	end.
