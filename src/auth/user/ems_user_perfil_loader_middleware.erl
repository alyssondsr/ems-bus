%%********************************************************************
%% @title Module ems_user_perfil_loader_middleware
%% @version 1.0.0
%% @doc Module responsible for load user from filesystem or db
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_perfil_loader_middleware).

-include("../include/ems_config.hrl").
-include("../include/ems_schema.hrl").

-export([insert_or_update/5, is_empty/1, size_table/1, clear_table/1, reset_sequence/1, get_filename/0, check_remove_records/1]).


-spec is_empty(fs | db) -> boolean().
is_empty(db) ->	mnesia:table_info(user_perfil_db, size) == 0;
is_empty(fs) ->	mnesia:table_info(user_perfil_fs, size) == 0.
	

-spec size_table(fs | db) -> non_neg_integer().
size_table(db) -> mnesia:table_info(user_perfil_db, size);
size_table(fs) -> mnesia:table_info(user_perfil_fs, size).
	

-spec clear_table(fs | db) -> ok | {error, efail_clear_ets_table}.
clear_table(db) ->	
	case mnesia:clear_table(user_perfil_db) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end;
clear_table(fs) ->	
	case mnesia:clear_table(user_perfil_fs) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end.
	
	
-spec reset_sequence(fs | db) -> ok.
reset_sequence(db) -> 
	ems_db:init_sequence(user_perfil_db, 0),
	ok;
reset_sequence(fs) ->	
	ems_db:init_sequence(user_perfil_fs, 0),
	ok.
	
	
-spec check_remove_records(list()) -> ok.	
check_remove_records(_Ids) ->  ok.

%% internal functions

-spec get_filename() -> list(tuple()).
get_filename() -> 
	Conf = ems_config:getConfig(),
	Conf#config.user_perfil_path_search.
	
	
-spec insert_or_update(map() | tuple(), tuple(), #config{}, atom(), insert | update) -> {ok, #service{}, atom(), insert | update} | {ok, skip} | {error, atom()}.
insert_or_update(Map, CtrlDate, Conf, SourceType, _Operation) ->
	try
		case ems_user_perfil:new_from_map(Map, Conf) of
			{ok, NewRecord = #user_perfil{codigo = Codigo, ctrl_hash = CtrlHash}} -> 
				Table = ems_user_perfil:get_table(SourceType),
				case ems_user_perfil:find(Table, Codigo) of
					{error, enoent} -> 
						Id = ems_db:sequence(Table),
						User = NewRecord#user_perfil{id = Id,
													 ctrl_insert = CtrlDate},
						{ok, User, Table, insert};
					{ok, CurrentRecord = #user_perfil{ctrl_hash = CurrentCtrlHash}} ->
						case CtrlHash =/= CurrentCtrlHash of
							true ->
								?DEBUG("ems_user_perfil_perfil_loader_middleware update ~p from ~p.", [Map, SourceType]),
								UserPerfil = CurrentRecord#user_perfil{
												 codigo = Codigo,
												 codigo_usuario = NewRecord#user_perfil.codigo_usuario,
												 codigo_cliente = NewRecord#user_perfil.codigo_cliente,
												 name = NewRecord#user_perfil.name,
												 ctrl_path = NewRecord#user_perfil.ctrl_path,
												 ctrl_file = NewRecord#user_perfil.ctrl_file,
												 ctrl_update = CtrlDate,
												 ctrl_modified = NewRecord#user_perfil.ctrl_modified,
												 ctrl_hash = NewRecord#user_perfil.ctrl_hash
											},
								{ok, UserPerfil, Table, update};
							false -> {ok, skip}
						end
				end;
			Error -> Error
		end

	catch
		_Exception:Reason -> {error, Reason}
	end.

