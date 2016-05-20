%%********************************************************************
%% @title Arquivo de configuração ErlangMS
%% @version 1.0.0
%% @doc Arquivo com configurações gerais de funcionamento de ErlangMS.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

%-ifndef(PRINT).
%-define(PRINT(Var), io:format("DEBUG: ~p", [??Var, Var])).
%-endif.

% Tamanho máximo do payload do POST. Por default é 1M
-define(HTTP_MAX_POST_SIZE, 1024 * 1024 * 1024).

% Nome do servidor
-define(SERVER_NAME, io_lib:format(<<"ErlangMS Development Version ~s">>, [case application:get_key(msbus, vsn) of 
																					{ok, Version} -> Version;
																					undefined -> "1"
																			end])).


% Caminho do diretório privado
-define(PRIV_PATH, ems_util:get_priv_dir()).

% Caminho do catálogo de serviços
-define(CONF_PATH, ?PRIV_PATH ++ "/conf").

% Caminho do favicon
-define(FAVICON_PATH, ?PRIV_PATH ++ "/favicon.ico").

% Caminho do catálogo de serviços
-define(CATALOGO_PATH, ?CONF_PATH ++ "/catalog.conf").

% Caminho do arquivo de configuração
-define(CONF_FILE_PATH, ?CONF_PATH ++ "/emsbus.conf").

% Caminho inicial para os arquivos estáticos
-define(STATIC_FILE_PATH, ?PRIV_PATH ++ "/www").

% Propriedade TCP Timeout para envio do response
-define(TCP_SEND_TIMEOUT, 30000).

% Number of TCP connections that have completed the SYN/ACK handshake and not yet been accepted by user
-define(TCP_BACKLOG, 128).

% Armazena em cache as novas requisições por REQ_CACHE_SYNC_CHECKPOINT ms antes de persistir no banco
-define(REQ_CACHE_SYNC_CHECKPOINT, 6000).

% Armazena o buffer do log a cada LOG_FILE_CHECKPOINT ms (Aumente este valor se existir muita contenção na escrita em disco)
-define(LOG_FILE_CHECKPOINT, 6000).  

% Arquiva o log a cada LOG_ARCHIVE_CHECKPOINT ms
-define(LOG_ARCHIVE_CHECKPOINT, 10000 * 60 * 60 * 4).  % Por default são 4 horas

% Quantos workers HTTP instanciar se não especificado no arquivo de configuração
-define(MAX_HTTP_WORKER, 12).

% Quantos workers HTTP são permitidos especificar no arquivo de configuração (1 até MAX_HTTP_WORKER_RANGE)
-define(MAX_HTTP_WORKER_RANGE, 1000).  % a cada 4 horas

% How long wait a request in accept
-define(TCP_ACCEPT_CONNECT_TIMEOUT, 60000). % 1 minute

% Ho long to wait for the http request
-define(TCP_RECV_TIMEOUT, 1000). % 1 second

% How long to wait a service end
-define(EMS_DEFAULT_SERVICE_TIMEOUT, 15000). % 15 seconds


%  Definition of file config
-record(config, {tcp_listen_address,    		%% Quais IPs das interfaces de rede que o barramento vai ouvir
				 tcp_listen_address_t,			%% Quais IPs das interfaces de rede que o barramento vai ouvir (formato de tupla para inet)
				 tcp_port, 						%% Qual a porta que será utilizada para o barramento
 				 tcp_keepalive, 				%% Propriedade keepalive do TCP (true/false)
				 tcp_nodelay, 					%% Propriedade nodelay do TCP (true/false)
				 tcp_max_http_worker,			%% Quantos workers serão criados para cada listener
				 tcp_allowed_address,			%% Faixa de ips que são permitidos acessar os serviços do barramento
				 tcp_allowed_address_t,			%% Faixa de ips que são permitidos acessar os serviços do barramento (formato de tupla para inet)
				 tcp_accept_timeout,			%% Timeout to accept requests
				 tcp_recv_timeout,				%% timeout for receive packets
				 log_file_dest,					%% Caminho para a pasta dos logs do barramento
				 log_file_checkpoint,			%% De quanto em quanto tempo será descarregado os buffers do módulo msbus_logger (DEFAULT 6 segundos)
				 cat_host_alias, 				%% Lista (Chave-Valor) com os names alternativos para os hosts. Ex.: ["negocio01", "192.168.0.103", "negocio02", "puebla"]
				 cat_host_search,				%% Lista de hosts para pesquisar os serviços
				 cat_node_search,				%% Lista de nodes para pesquisar os serviços
				 ems_hostname,					%% Nome da maquina onde o barramento está sendo executado
				 ems_host,						%% Atom do name da maquina onde o barramento está sendo executado
				 ems_file_dest,					%% Nome do arquivo de configuração (útil para saber o local do arquivo)
				 ems_debug,						%% Modo debug (true/false)
 				 ems_default_service_timeout,	%% Default service timeout to wait for request when no timeout parameter is especified in catalog
				 ldap_tcp_port, 				%% ldap tcp port
				 ldap_datasource = "",			%% ldap datasource
				 ldap_sql_find_user = "",		%% sql to find user
				 ldap_admin = "",				%% admin of ldap
				 ldap_password_admin = ""		%% password of admin ldap
				 
		 }). 	



