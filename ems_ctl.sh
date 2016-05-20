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
# 2) Como instânciar um node ErlangMS com nome padrão "emsbus": 
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
#         Exemplo 2: ./ems_ctl.sh console   (vai conectar na instância padrão emsbus)
#


# Parâmetros
ems_ctl_version="1.0"
ems_cookie=erlangms
ems_node="emsbus"
ems_init="application:start(ems_bus)"
ems_stop="application:stop(ems_bus)."
ems_log_conf="./priv/conf/elog"
ems_hostname=`hostname`
ems_current_dir=`pwd`
ems_ctl_node="ems_shell_`date +"%I%M%S"`@$ems_hostname"
ems_path="-pa $ems_current_dir/ebin deps/jsx/ebin deps/poolboy/ebin"

# Conectar no terminal de uma instância ErlangMS
function console() {
	node_name=$(format_node_name $1)
	echo "Conectando na instância ErlangMS $node_name..."
	erl -remsh $node_name -sname $ems_ctl_node \
		-setcookie $ems_cookie \
		$ems_path \
		-boot start_sasl -config $ems_log_conf \
		
}

# Instanciar um node ErlangMS
function start() {
	node_name=$(format_node_name $1)
	status $node_name
	if [ $? != 0 ]; then
		console $node_name
	else
		if [ "$is_daemon" == "daemon" ]; then
			echo "Starting instance ErlangMS $node_name como daemon ..."
			erl -detached $ems_path \
				-sname $node_name -setcookie $ems_cookie \
				-eval $ems_init -boot start_sasl -config $ems_log_conf 
		else
			echo "Starting instance ErlangMS $node_name..."
			erl $ems_path \
				-sname $node_name -setcookie $ems_cookie -eval $ems_init \
				-boot start_sasl -config $ems_log_conf 
		fi
	fi
}


# Verifica se uma instância ErlangMS está executando
function status(){
	node_name=$(format_node_name $1)
	echo "Checking for an instance $node_name running..."
	cmd_eval="io:format( \"~p\", [ ems_util:node_is_live( list_to_atom( \"$node_name\" ) ) ] ), halt()"
	echo $cmd_eval
	is_running=`erl -noshell $ems_path \
				-boot start_clean  \
				-sname $ems_ctl_node \
				-setcookie $ems_cookie \
				-eval '$cmd_eval'`
	echo $is_running
	if [ "$is_running" == "1" ]; then
		echo "$node_name is already running!"
		return 1
	else
		echo "$node_name is stopped!"
		return 0
	fi
}

function list_nodes(){
	epmd -names
}

function format_node_name(){
	node_name=$1
	if [ "$node_name" == "" ]; then
		node_name="emsbus@$ems_hostname"
	fi
	if [ `expr index "$node_name" "@"` == 0 ]; then
		node_name="$node_name@$ems_hostname" 
	fi
	echo $node_name
}


# header do comando
clear
echo "ErlangMS Control Manager [ Hostname: $ems_hostname,  Version: $ems_ctl_version, Shell $ems_ctl_node ]"

# Aciona o comando escolhido
case "$1" in

	  'start')
			start $2
	  ;;

	  'start_daemon')
			Node="$2"
			start "$Node" "daemon"
	  ;;

	  'start-daemon')
			Node="$2"
			start "$Node" "daemon"
	  ;;

	  'console')
			console $2
	  ;;

	  'list')
			list_nodes
	  ;;

	  'status')
			status $2
	  ;;

	  *)
			if [ $1 != "" ]; then
				echo "Uso: ems_ctl.sh start|start-daemon|console|list|status [node]"
			else
				start $2
			fi
	  ;;

esac
