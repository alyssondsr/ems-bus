ErlangMS
=====

ErlangMS is a platform developed in Erlang/OTP to facilitate the integration of systems through a service-oriented approach for the systems of the University of Brazilia. This work is the result of efforts made in the Master of Applied Computing at the University of Brasilia by graduate student *Everton Vargas agilar*. 

The platform consists of a Enterprise Service Bus (ESB), called *EmsBus*, and a *documented architecture* to implement the services in Erlang, Java and future in .NET Framework languages.

###Main design features

* Back-end modular and multi-platform;

* Communication services is through asynchronous messages and requests for services by customers through HTTP/REST and LDAP;

* Published services are specified in a service catalog in JSON format;

* Services can be published in one or more nodes in the cluster (eg, Containers JBoss in Java EE ou native Erlang node), to avoid single points of failure (SPOFs);

* Support HTTP Authentication;
 
* Preliminary support Lightweight Directory Access Protocol (LDAP v3) for authentication;

* OAuth2 authentication (in progress);

* Front-end lightweight and optimized for service-oriented computing in HTML5 e Angular 2 (Project in https://github.com/eliot-framework/eliot).



*See the platform architecture em https:*//github.com/erlangMS/msbus/blob/master/doc/arquitetura_erlangms.pdf


###Running the bus
-----------------------

If the project is already installed and configured, run the *start* command, according to the operating system:

If you are in Linux, type:

```console
$ ./start.sh
(msbus@puebla)1> ErlangMS Development Version 1.0
Initializing the module pool:
   Module msbus_eventmgr with 1 worker.
   Module msbus_catalogo with 2 workers.
   Module msbus_user with 2 workers.
   Module msbus_cache with 1 worker.
   Module msbus_http_server with 1 worker.
   Module msbus_ldap_server with 1 worker.
   Module msbus_request with 1 worker.
   Module msbus_http_worker with 3 workers.
   Module msbus_ldap_worker with 3 workers.
   Module msbus_health with 6 workers.
   Module msbus_dispatcher with 6 workers.
   Module msbus_static_file_service with 6 workers.
   Module msbus_user_service with 2 workers.
   Module msbus_catalogo_service with 2 workers.
   Module msbus_info_service with 2 workers.
   Module msbus_favicon_service with 2 workers.
   Module msbus_options_service with 2 workers.
   Module msbus_ldap_service with 2 workers.
   Module msbus_health_service with 12 workers.
config_file_dest: /home/viper/.erlangms/msbus@puebla.conf
cat_host_alias: #{<<"local">> => <<"puebla">>}
cat_host_search: local
cat_node_search: node01, node02, node03
log_file_dest: logs
log_file_checkpoint: 6000ms
tcp_listen_address: ["127.0.0.1"]
tcp_allowed_address: []
tcp_port: 2301
tcp_keepalive: true
tcp_nodelay: true
tcp_max_http_worker: 128
Portal Api Management: http://127.0.0.1:2301/portal/index.html
msbus@puebla started in 244ms.
Listening http packets on 127.0.0.1:2301.
Listening ldap packets on 127.0.0.1:2389.
```


If everything is OK, go to http://localhost:2301/samples/hello_world on your browser.

*{"message": "It works!!!"}*


###Running multiple instances of bus

You can start multiple instances of the bus (locally or on different servers) to avoid SPOFs.

```console
$ ./ems_ctl.sh start bus_01

ErlangMS Control Manager [ Hostname: puebla,  Version: 1.0 ]
Checking for an instance bus_01 @ puebla running...
bus_01@puebla is stopped!
Starting instance ErlangMS bus_01@puebla...
...


$ ./ems_ctl.sh start bus_02

ErlangMS Control Manager [ Hostname: puebla,  Version: 1.0 ]
Checking for an instance bus_02 @ puebla running...
bus_02@puebla is stopped!
Starting instance ErlangMS bus_01@puebla...
...

```



###Compiling the project:

Check the wiki below to see how to download the project, compile and configure: https://github.com/erlangMS/msbus/wiki/Instalar-o-EBS-ErlangMS-msbus


###Project dependencies for the bus
------------------------

* Erlang R18 - <http://www.erlang.org/download.html>
* jsx - encode/decore JSON <https://github.com/talentdeficit/jsx>


###Implementing a helloworld_service in Java EE
------------------------

1) First, you must specify the service
```console
{
	"name" : "/samples/hello_world_java",
	"comment": "Hello World in Java",
	"owner": "samples",
	"version": "1",
	"service" : "br.erlangms.samples.service.HelloWorldFacade:helloWorld",
	"url": "/samples/hello_world_java",
	"host": "local",
	"type": "GET",
	"APIkey":"true",
	"lang" : "java"
}
```

*This contract is saved in the catalog directory of the bus (localized in the folder priv/catalog)*

2) Service implementation

```console
package br.erlangms.samples.service;

import javax.ejb.Singleton;
import javax.ejb.Startup;
import br.erlangms.EmsServiceFacade;
import br.erlangms.IEmsRequest;

@Singleton
@Startup
public class HelloWorldFacade extends EmsServiceFacade {

	 public String helloWorld(IEmsRequest request) {
		    return "Hello World Java!!!";
	 }

}

```

The architecture provides that the services are implemented according to the design *Domain Driven Design (DDD)* but for simplicity only the facade of the service is displayed here.

3) Consuming the service

curl:
```
curl -X GET localhost:2301/samples/hello_world
{"message": "Hello World!!!"}
```

Log in the bus:
```
REQUEST ROWID <<"GET#/samples/hello_world">>.
CAST helloworld_service:execute em puebla {RID: 1457890196200613870, URI: /samples/hello_world}.
GET /samples/hello_world HTTP/1.1 {
        RID: 1457890196200613870
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8:
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36
        Content-Type: application/json
        Payload: 
        Service: helloworld_service:execute
        Query: []
        Authorization: 
        Status: 200 <<ok>> (6ms)
        Send: ok
}
```





###Documentation of functional programming
-----------------------------------------

Documentação sobre Erlang

<http://www.erlang.org/>

Excellent online book about distributed programming in Erlang

<http://learnyousomeerlang.com/>

List of articles about programming in Erlang

<https://github.com/0xAX/erlang-bookmarks/blob/master/ErlangBookmarks.md>
