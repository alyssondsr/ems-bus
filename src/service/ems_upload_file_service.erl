%%********************************************************************
%% @title Module ems_upload_file_service
%% @version 1.0.0
%% @doc ems_upload_file_service
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_upload_file_service).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([execute/1]).

execute(Request) ->	ems_util:save_from_file_req(Request).
   
    
