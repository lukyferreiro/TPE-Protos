# TPE-PDC

    Tomas Alvarez Escalante 60127
    Alejo Francisco Caeiro 60692
    Lucas Agustin Ferreiro 61595
    Roman Gomez Kiss 61003

-----------------------------------------------------------------------------------
# Instalacion y configuracion

Para correr el proyecto hay que posicionar en la carpeta root y ejecutar:

```
CC=gcc make all     #Para compilar con GCC
CC=clang make all   #Para compilar con CLANG
```

Para iniciar el servidor, moverse a la carpeta src y ejecutar ./socks5d 

Al levantar el servidor, se pueden utilizar los siguientes argumentos:

    -h               Imprime la ayuda y termina.
    -l <SOCKSaddr>   Dirección IPv4 o IPv6 donde servirá el proxy SOCKS.
    -L <mng-addr>    Dirección IPv6 o IPV6 donde servirá el servicio de administrador.
    -p <SOCKS-port>  Puerto entrante conexiones SOCKS.
    -P <mgn-port>    Puerto entrante conexiones configuracion
    -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.
    -v               Imprime información sobre la versión y termina.
    -N               Deshabilita los passwords disectors.\n"

Para correr el cliente administrador, moverse a la carpeta src y ejecutar ./alpha_manager <addr> <port> 

Tanto <addr> como <port> dependen de como fue levantado el servidor proxy. 

Por default estos valores son 127.0.0.1 y 8080, pero pueden ser modificados con los flags -L y -P cuando se levanta ./socks5d

La shell del cliente cuenta con los siguientes comandos:

    help                Imprime todos los comandos
    list <page>         Lista los usuarios. Maximo 25 por pagina.
    hist                Devuelve cantidad de conexiones historicas
    conc                Devuelve cantidad de conexiones concurrentes
    bytes               Devuelve cantidad de bytes transferidos
    add <user:password>     Agrega un usuario
    del <user>          Elimina un usuario 
    auth-on             Habilita la autenticacion
    auth-off            Desabilita la autenticacion
    checkauth           Devuelve el estado de la autenticacion
    sniff-on            Habilita el sniffing
    sniff-off           Desabilita el sniffing
    checksniff          Devuelve el estado del sniffing

-----------------------------------------------------------------------------------
# Ubicación de los materiales

En la carpeta src es donde se generaran los ejecutables ./socks5d y ./alpha_manager

Dentro de esta misma carpeta se encuentran todos los archivos desarrollados en el trabajo:

    En /auth se encuentra el manejo del parser de AUTH
    En /buffer se encuentra el manejo de los buffers
    En /hello se encuentro el manejo del parser de HELLO
    En /include se encuentran todos los .h
    En /logger se encuentra el manejo de los logs
    En /manager_protocol se encuentra el manejo del cliente administrador
    En /pop3 se encuentra el manejo del parser de SNIFFER
    En /request se encuentra el manejo del parser de REQUEST
    En /selector se encuentra el manejo del selector
    En /socks5 se encuentra el manejo de las conexiones entrantes al servidor proxy SOCKSv5
    En /stm se encuentra el manejo de la maquina de estados
    En /test se encuentran los testos propuestos por la catedra (no fueron modificados por los integrantes)
    En /utils se encuentran archivos de utilidad, como el manejor de la metricas, entre otros.

Por otro lado, dentro de la carpeta docs podremos encontrar el informe


-----------------------------------------------------------------------------------
# Debug

En el archivo logger.c existe una define 'IS_DEBUG', si este esta descomentado, se podran observar
algunos logs de debug mientras se usa el proxy.
