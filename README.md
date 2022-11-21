# TPE-PDC

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
    -v               Imprime información sobre la versión versión y termina.
    -N               Deshabilita los passwords disectors.\n"

Para correr el cliente administrador, moverse a la carpeta src y ejercutar ./alpha_manager <addr> <port>
Tanto <addr> como <port> dependen de como fue levantado el servidor proxy.
Por default estos valores son 127.0.0.1 y 8080, pero pueden ser modificados con los flags -L y -P cuando se levanta ./socks5d

-----------------------------------------------------------------------------------
# Ubicación de los materiales
