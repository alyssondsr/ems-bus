%%********************************************************************
%% @title Module ems_user_email
%% @version 1.0.0
%% @doc user class
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_email).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([new_from_map/2,
		 get_table/1,
		 find/2,
		 all/1]).


-spec new_from_map(map(), #config{}) -> {ok, #user_email{}} | {error, atom()}.
new_from_map(Map, _Conf) ->
	try
		{ok, #user_email{
					id = maps:get(<<"id">>, Map),
					codigo_pessoa = maps:get(<<"codigo_pessoa">>, Map),
					email = ?UTF8_STRING(maps:get(<<"email">>, Map)),
					type = maps:get(<<"type">>, Map, 1),
					ctrl_path = maps:get(<<"ctrl_path">>, Map, <<>>),
					ctrl_file = maps:get(<<"ctrl_file">>, Map, <<>>),
					ctrl_modified = maps:get(<<"ctrl_modified">>, Map, undefined),
					ctrl_hash = erlang:phash2(Map)
			}
		}
	catch
		_Exception:Reason -> 
			ems_logger:format_warn("ems_user_email parse invalid user specification: ~p\n\t~p.\n", [Reason, Map]),
			{error, Reason}
	end.


-spec get_table(fs | db) -> user_email_db | user_email_fs.
get_table(db) -> user_email_db;
get_table(fs) -> user_email_fs.

-spec find(user_email_fs | user_email_db, non_neg_integer()) -> {ok, #user{}} | {error, enoent}.
find(Table, Id) ->
	case mnesia:dirty_read(Table, Id) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.

-spec all(user_email_fs | user_email_db) -> list() | {error, atom()}.
all(Table) -> ems_db:all(Table).

