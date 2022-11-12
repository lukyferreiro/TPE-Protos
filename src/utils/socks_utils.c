#include "socks_utils.h"
#include "args.h"
#include "logger.h"
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h> 

int create_socket(struct socks5_args* args, addr_type addr_type) {

    int new_socket;
    struct sockaddr_in addr;
    struct sockaddr_in6 addr_6;

    int ip_version = (addr_type == ADDR_IPV4) ? AF_INET : AF_INET6;
    int port = args->socks_port;
    char* address4 = args->socks_addr;
    char* address6 = args->socks_addr6;

    new_socket = socket(ip_version, SOCK_STREAM, IPPROTO_TCP);
    if (new_socket < 0) {
        log(LOG_ERROR, "Cannot create socket");
        return -1;
    }

    // Setsockopt para IPv4
    if (setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        log(LOG_ERROR, "Cannot set socket options");
    }

    // Setsockopt para IPv6
    if (addr_type == ADDR_IPV6 && setsockopt(new_socket, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int)) < 0) {
        log(LOG_ERROR, "Cannot set socket options");
    }

    log(INFO, "Listening on TCP port %d", port);
    if (addr_type == ADDR_IPV4) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, address4, &addr.sin_addr.s_addr) <= 0) {
            log(DEBUG, "Cannot translate to IPv4 the address %s ", address4);
            close(new_socket);
            return -1;
        }
        if (bind(new_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            log(LOG_ERROR, "Cannot bind socket");
            close(new_socket);
            return -1;
        }
    } else {
        memset(&addr_6, 0, sizeof(addr_6));
        addr_6.sin6_family = AF_INET6;
        addr_6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, address6, &addr_6.sin6_addr) <= 0) {
            log(DEBUG, "Cannot translate to IPv6 the address %s", address6);
            close(new_socket);
            return -1;
        }

        if (bind(new_socket, (struct sockaddr*)&addr_6, sizeof(addr_6)) < 0) {
            log(LOG_ERROR, "Cannot bind socket");
            close(new_socket);
            return -1;
        }
    }

    if (listen(new_socket, MAX_PENDING_CONNECTIONS) < 0) {
        log(LOG_ERROR, "Cannot listen socket");
        close(new_socket);
        return -1;
    } else {
        log(INFO, "Waiting for new %s SOCKSv5 connection on TCP socket with address %s and fd: %d \n",
            addr_type == ADDR_IPV4 ? "IPv4" : "IPv6",
            addr_type == ADDR_IPV4 ? address4 : address6,
            new_socket);
    }

    return new_socket;
}