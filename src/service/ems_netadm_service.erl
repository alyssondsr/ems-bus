%%********************************************************************
%% @title Module ems_netadm_service
%% @version 1.0.0
%% @doc It provides information about cluster.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************tn************************************************

-module(ems_netadm_service).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([names/1, world/1, hostfile/1, hostname/1, localhost/1, memory/1, timestamp/1, 
		 threads/1, info/1, config/1, restart/1, pid/1, uptime/1, tasks/1]).
  
names(Request) -> 
	ContentData = case net_adm:names() of
		{ok, Names} -> ems_schema:to_json(Names);
		Error -> ems_schema:to_json(Error)
	end,
	{ok, Request#request{code = 200, 
						 response_data = ContentData}
	}.

world(Request) -> 
	try
		ContentData = [ atom_to_list(R) || R <- net_adm:world() ],
		{ok, Request#request{code = 200, 
							 response_data = ems_schema:to_json(ContentData)}
		}
	catch 
		_Exception:_Reason -> 
			{ok, Request#request{code = 200, 
								 response_data = <<"[]">>}
			}
	end.

hostfile(Request) -> 
	ContentData = net_adm:host_file(),
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json(ContentData)}
	}.

localhost(Request) -> 
	ContentData = {ok, net_adm:localhost()},
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json(ContentData)}
	}.
	
hostname(Request) -> 
	Conf = ems_config:getConfig(),
	ContentData = {ok, Conf#config.ems_hostname},
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json(ContentData)}
	}.
	
memory(Request) -> 
	ContentData = [{erlang:atom_to_binary(K, utf8), erlang:trunc(V / 1024 / 1024)} || {K,V} <- erlang:memory(), K =/= system andalso 
																												K =/= atom andalso 
																												K =/= atom_used andalso 
																												K =/= code andalso 
																												K =/= binary],
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json(ContentData)}
	}.
	
timestamp(Request) -> 
	ContentData = {ok, ems_util:timestamp_str()},
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json(ContentData)}
	}.

threads(Request) -> 
	ContentData = {ok, length(erlang:processes())},
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json(ContentData)}
	}.
	
info(Request) -> 
	ContentData = ranch_info(),
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json(ContentData)}
	}.

config(Request) -> 
	ContentData = lists:flatten(io_lib:format("~p", [ems_config:getConfig()])),
	{ok, Request#request{code = 200, 
						 content_type = <<"text/plain">>,
						 response_data = ContentData}
	}.

restart(Request) -> 
	init:restart(),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

pid(Request) -> 
	ContentData = {ok, list_to_integer(os:getpid())},
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json(ContentData)}
	}.

uptime(Request) -> 
	ContentData = {ok, ems_util:uptime_str()},
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json(ContentData)}
	}.
	
tasks(Request) -> 
	ContentData = {ok, statistics(total_active_tasks)},
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json(ContentData)}
	}.
	

%% internal functions

ranch_info() ->	ranch_info(ranch:info(), []).

ranch_info([], R) -> R;
ranch_info([{Listener, Info}|T], R) ->
	Info2 = [{erlang:atom_to_binary(K, utf8), ranch_value_to_binary(V)} || {K,V} <- Info,  K =/= pid andalso 
																						   K =/= protocol_options andalso 
																						   K =/= pid andalso 
																						   K =/= transport_options],
	ListenerBin = erlang:atom_to_binary(Listener, utf8),
	ranch_info(T, [{ListenerBin, maps:from_list(Info2)} | R]).

ranch_value_to_binary(V) when is_integer(V) -> integer_to_binary(V);
ranch_value_to_binary(V) when is_atom(V) -> erlang:atom_to_binary(V, utf8);
ranch_value_to_binary(V) when is_list(V) -> list_to_binary(V);
ranch_value_to_binary({A,B,C,D}) -> list_to_binary(io_lib:format("{~p,~p,~p,~p}", [A,B,C,D]));
ranch_value_to_binary(V) -> V.
