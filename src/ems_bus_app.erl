-module(ems_bus_app).

-behaviour(application).

-include("../include/ems_config.hrl").
-include("../include/ems_schema.hrl").


%% Application callbacks
-export([start/0, start/2, stop/0, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start() ->
    application:start(?MODULE).

stop() ->
    application:stop(?MODULE).
    
start(_StartType, StartArgs) ->
	case ems_config:start() of
		{ok, _Pid} ->
			T1 = ems_util:get_milliseconds(),
			Config = ems_config:getConfig(),
			ems_logger:start(),
			ems_logger:info("~n~s", [?SERVER_NAME]),

			case ems_catalog:init_catalog() of
				ok ->
					Ret = ems_bus_sup:start_link(StartArgs),

					%% show config parameters 
					ems_logger:info("ems_file_dest: ~p", [Config#config.ems_file_dest]),
					ems_logger:info("ems_default_service_timeout: ~p", [Config#config.ems_default_service_timeout]),
					
					ems_logger:info("cat_host_alias: ~p", [Config#config.cat_host_alias]),
					ems_logger:info("cat_host_search: ~s", [ems_util:join_binlist(Config#config.cat_host_search, ", ")]),
					ems_logger:info("cat_node_search: ~s", [ems_util:join_binlist(Config#config.cat_node_search, ", ")]),
					
					ems_logger:info("log_file_dest: ~s", [Config#config.log_file_dest]),
					ems_logger:info("log_file_checkpoint: ~pms", [Config#config.log_file_checkpoint]),
					
					ems_logger:info("tcp_listen_address: ~p", [Config#config.tcp_listen_address]),
					ems_logger:info("tcp_allowed_address: ~p", [Config#config.tcp_allowed_address]),
					ems_logger:info("tcp_port: ~p", [Config#config.tcp_port]),
					ems_logger:info("tcp_keepalive: ~p", [Config#config.tcp_keepalive]),
					ems_logger:info("tcp_nodelay: ~p", [Config#config.tcp_nodelay]),
					ems_logger:info("tcp_accept_timeout: ~p", [Config#config.tcp_accept_timeout]),
					ems_logger:info("tcp_recv_timeout: ~p", [Config#config.tcp_recv_timeout]),
					
					ems_logger:info("ldap_tcp_port: ~p", [Config#config.ldap_tcp_port]),
					ems_logger:info("ldap_datasource: ~s", [Config#config.ldap_datasource]),
					ems_logger:info("ldap_admin: ~s", [Config#config.ldap_admin]),
					
					ems_logger:debug("In debug mode: ~p~", [Config#config.ems_debug]),

					ems_logger:info("Server ~s started in ~pms.", [node(), ems_util:get_milliseconds() - T1]),

					%%register_events(),

					Ret;
				{error, Reason} -> 
					ems_logger:stop(),
					io:format("Error processing catalog files: ~p.\n", [Reason]),
					{error, Reason}
			end;
		{error, Reason} ->
			io:format("Error processing configuration file: ~p.\n", [Reason]),
			{error, finish}
	end.

stop(_State) ->
    ems_bus_sup:stop(),
    ems_logger:stop(),
	ems_config:stop(),
    ok.
    
register_events() ->
   	ems_eventmgr:adiciona_evento(new_request),
	ems_eventmgr:adiciona_evento(ok_request),
	ems_eventmgr:adiciona_evento(erro_request),
	ems_eventmgr:adiciona_evento(close_request),
	ems_eventmgr:adiciona_evento(send_error_request),

    ems_eventmgr:registra_interesse(ok_request, fun(_Q, {_, #request{worker_send=Worker}, _} = R) -> 
														gen_server:cast(Worker, R)
												end),

	ems_eventmgr:registra_interesse(erro_request, fun(_Q, R) -> 
														ems_logger:log_request(R) 
												  end).
    
													 
    
