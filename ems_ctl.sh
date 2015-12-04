#!/bin/bash
#
# ErlangMS Control Manager
# Autor: Everton de Vargas Agilar
# Data: 03/12/2015
#


# Documentação sobre o comando ems_ctl.sh
#--------------------------------------------------------------------
# 1) Opções que podem ser utilizadas no comando ems_ctl.sh
#     $1 -> opção do comando (start, start-daemon, stop e console)
#     $2 -> nome do node que quer instanciar ou conectar
#
#
# 2) Como instânciar um node ErlangMS com nome padrão "msbus": 
#    
#            ./ems_ctl.sh start
#
#
# 3) Instanciar um node ErlangMS com um node específico): 
#
#            ./ems_ctl.sh start nome_do_node
#
#         Exemplo 1: ./ems_ctl.sh start node_01
#         Exemplo 2: ./ems_ctl.sh start prod_esb
#
#
# 4) Instanciar um node ErlangMS como daemon
#
#            ./ems_ctl.sh start_daemon
#
# 5) Conectar em uma instância ErlangMS
#
#            ./ems_ctl.sh console nome_do_node
#
#         Exemplo 1: ./ems_ctl.sh console node_01
#         Exemplo 2: ./ems_ctl.sh console   (vai conectar na instância padrão msbus)
#


# Parâmetros
ems_cookie="erlangms"
ems_node="msbus"
ems_init="msbus:start()"
ems_stop="msbus:stop()"
ems_log_conf="./priv/conf/elog"
ems_hostname=`hostname`
ems_ctl_node="msbus_shell_`date +"%I%M%S"`@$ems_hostname"


# Conectar no terminal de uma instância ErlangMS
function console() {
	node_name=$1
	if [ "$node_name" == "" ]; then
		remote_node="msbus@$hostname"
	fi
	echo "Conectando na instância ErlangMS $node_name..."
	erl -sname $ems_ctl_node -setcookie $ems_cookie -remsh $node_name
}

# Instanciar um node ErlangMS
function start() {
	./build.sh
	node_name=$1
	if [ "$node_name" == "" ]; then
		node_name="msbus@$ems_hostname"
	fi
	status $node_name
	if [ $? != 0 ]; then
		console $node_name
	else
		echo "Iniciando instância ErlangMS $node_name..."
		erl -pa ../msbus/ebin deps/jsx/ebin deps/poolboy/ebin -sname $node_name -setcookie $ems_cookie -eval $ems_init -boot start_sasl -config $ems_log_conf 
	fi
}

# Instanciar um node ErlangMS como daemon
function start_daemon() {
	./build.sh
	node_name=$1
	hostname=`hostname`
	if [ "$node_name" == "" ]; then
		node_name="msbus@$hostname"
	fi
	echo "Iniciando instância ErlangMS $node_name como daemon..."
	erl -detached -pa ../msbus/ebin deps/jsx/ebin deps/poolboy/ebin -sname $node_name -setcookie $ems_cookie -eval $ems_init -boot start_sasl -config $ems_log_conf
	echo "ok."
}

# Parar uma instância de um node ErlangMS
function stop() {
	remote_node=$1
	hostname=`hostname`
	if [ "$remote_node" == "" ]; then
		remote_node="msbus@$hostname"
	fi
	echo "Parando instância ErlangMS $remote_node..."
	my_node="msbus_shell_`date +"%I%M%S"`"
	erl -sname $my_node -setcookie $ems_cookie -remsh $remote_node -eval $ems_stop
}

# Verifica se uma instância ErlangMS está executando
function status(){
	remote_node=$1
	if [ "$remote_node" == "" ]; then
		remote_node="msbus@$ems_hostname"
	fi
	echo "Verificando se há uma instância $remote_node executando..."
	is_running=`erl -noshell -pa ../msbus/ebin -boot start_clean -sname $ems_ctl_node \
			   -setcookie erlangms -eval 'io:format("~p", [ msbus_util:node_is_live( '$remote_node' ) ] ), halt()'`
	if [ "$is_running" == "1" ]; then
		echo "$remote_node já está executando!"
		return 1
	else
		echo "$remote_node está parado!"
		return 0
	fi
}


# header do comando
clear
echo "ErlangMS Control Manager [ Version 1.0 ]"

# Aciona o comando escolhido
case "$1" in

	  'start')
			start $2
	  ;;

	  'start_daemon')
			start_daemon $2
	  ;;

	  'start-daemon')
			start_daemon $2
	  ;;

	  'console')
			console $2
	  ;;

	  'stop')
			stop $2
	  ;;

	  'status')
			status $2
	  ;;

	  *)
			start $2
	  ;;

esac
