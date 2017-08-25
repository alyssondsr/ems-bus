%%********************************************************************
%% @title Module ems_auth_user
%% @version 1.0.0
%% @doc Module responsible for authenticating users.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_auth_user).

-include("../include/ems_config.hrl").
-include("../include/ems_schema.hrl").
    
-export([authenticate/2]).

authenticate(Service = #service{authorization = AuthorizationMode}, Request) ->
	case AuthorizationMode of
		http_basic -> do_basic_authorization(Service, Request);
		oauth2 ->	do_bearer_authorization(Service, Request);	
		oauth1 -> 	{do_mac_authorization(Service, Request),<<>>,<<>>};
		_ -> {ok, public, <<>>}
	end.



%%====================================================================
%% Internal functions
%%====================================================================


do_basic_authorization(_, #request{authorization = undefined}) -> {error, access_denied};
do_basic_authorization(_, #request{authorization = <<>>}) -> {error, access_denied};
do_basic_authorization(Service, Req = #request{authorization = Authorization}) ->
	case ems_http_util:parse_basic_authorization_header(Authorization) of
		{ok, Login, Password} ->
			case ems_user:find_by_login_and_password(list_to_binary(Login), list_to_binary(Password)) of
				{ok, User} -> do_check_grant_permission(Service, Req, User, <<>>);
				{error, Reason} = Error -> 
					ems_logger:warn("ems_auth_user do_basic_authorization error. Login: ~p  Reason: ~p.", [Login, Reason]),
					Error
			end;
		{error, Reason} = Error2 -> 
			ems_logger:warn("ems_auth_user do_basic_authorization error. Reason: ~p.", [Reason]),
			Error2
	end.

	
do_bearer_authorization(_, #request{authorization = <<>>}) -> {error, access_denied};
do_bearer_authorization(Service, Req = #request{authorization = undefined}) ->
	AccessToken = ems_request:get_querystring(<<"token">>, <<"access_token">>, <<>>, Req), % a querystring pode ser token ou access_token
	do_oauth2_check_access_token(AccessToken, Service, Req);
do_bearer_authorization(Service, Req = #request{authorization = Authorization}) ->	
	case ems_http_util:parse_bearer_authorization_header(Authorization) of
		{ok, AccessToken} ->  do_oauth2_check_access_token(AccessToken, Service, Req);
		{error, Reason} = Error -> 
			ems_logger:warn("ems_auth_user bearer_authorization error. Reason: ~p.", [Reason]),
			Error
	end.

%%%%%%%%%%%%% MAC Token %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
do_mac_authorization(_, Req = #request{authorization = <<>>}) -> 	ems_oauth1:verify_token(Req);
do_mac_authorization(Service, Req = #request{authorization = undefined}) ->
	oauth2ems_mac:verify_token(Req);
do_mac_authorization(Service, Req = #request{authorization = Authorization}) ->	
	oauth2ems_mac:verify_token(Req).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
	

	%PrivateKey = ems_util:open_file(?SSL_PATH ++  "/" ++ binary_to_list(<<"private_key.pem">>)),
	%TextPlain = ems_util:decrypt_private_key(AccessToken,PrivateKey),
	%?DEBUG("TextPlain ~p", [TextPlain]).


do_oauth2_check_access_token(<<>>, _, _) -> {error, access_denied};
do_oauth2_check_access_token(AccessToken, Service, Req) ->
	case oauth2:verify_access_token(AccessToken, undefined) of
		{ok, {[], [{<<"client">>, User}|_]}} -> 
			do_check_grant_permission(Service, Req, User, AccessToken);
		{error, Reason} = Error -> 
			ems_logger:warn("ems_auth_user check_access_token error. Reason: ~p.", [Reason]),
			Error
	end.
	

-spec do_check_grant_permission(#service{}, #request{}, #user{}, binary()) -> {ok, #user{}} | {error, access_denied}.
do_check_grant_permission(Service, Req, User, AccessToken) ->
	case ems_user_permission:has_grant_permission(Service, Req, User) of
		true -> {ok, User, AccessToken};
		false -> 
			ems_logger:warn("ems_auth_user check_grant_permission error. User: ~p. Reason: access_denied."),
			{error, access_denied}
	end.



