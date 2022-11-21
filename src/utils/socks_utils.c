// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "socks_utils.h"
#include "args.h"
#include "logger.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

struct socks5_args socks5_args;

int create_socket(struct socks5_args* args, addr_type addr_type, bool is_udp) {

    struct sockaddr_in addr;
    struct sockaddr_in6 addr_6;
    char* udp_or_tcp = is_udp ? "UDP" : "TCP";
    int ip_version = (addr_type == ADDR_IPV4) ? AF_INET : AF_INET6;
    char* addr_description = (addr_type == ADDR_IPV4) ? "IPv4" : "IPv6";
    int type = is_udp ? SOCK_DGRAM : SOCK_STREAM;
    int protocol = is_udp ? IPPROTO_UDP : IPPROTO_TCP;
    char* address4 = is_udp ? socks5_args.mng_addr : socks5_args.socks_addr;
    char* address6 = is_udp ? socks5_args.mng_addr6 : socks5_args.socks_addr6;
    int port = is_udp ? socks5_args.mng_port : socks5_args.socks_port;

    int new_socket = socket(ip_version, type, protocol);

    if (new_socket < 0) {
        logger(LOG_ERROR, "Cannot create socket");
        return -1;
    }

    // Setsockopt para IPv4
    if (!is_udp && setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        logger(LOG_ERROR, "Cannot set socket options");
    }

    // Setsockopt para IPv6
    if (addr_type == ADDR_IPV6 && setsockopt(new_socket, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int)) < 0) {
        logger(LOG_ERROR, "Cannot set socket options");
    }

    logger(INFO, "Listening on %s port %d", udp_or_tcp, port);

    if (addr_type == ADDR_IPV4) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, address4, &addr.sin_addr.s_addr) <= 0) {
            logger(DEBUG, "Cannot translate to IPv4 the address %s", address4);
            close(new_socket);
            return -1;
        }
        if (bind(new_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            logger(LOG_ERROR, "Cannot bind socket");
            close(new_socket);
            return -1;
        }
    } else {
        memset(&addr_6, 0, sizeof(addr_6));
        addr_6.sin6_family = AF_INET6;
        addr_6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, address6, &addr_6.sin6_addr) <= 0) {
            logger(DEBUG, "Cannot translate to IPv6 the address %s", address6);
            close(new_socket);
            return -1;
        }

        if (bind(new_socket, (struct sockaddr*)&addr_6, sizeof(addr_6)) < 0) {
            logger(LOG_ERROR, "Cannot bind socket");
            close(new_socket);
            return -1;
        }
    }

    if (!is_udp && listen(new_socket, MAX_PENDING_CONNECTIONS) < 0) {
        logger(LOG_ERROR, "Cannot listen socket");
        close(new_socket);
        return -1;
    } else {
        logger(INFO, "Opened %s %s socket (%d) for %s with address %s \n", udp_or_tcp, addr_description, new_socket, is_udp ? "manager" : "SOCKSv5", addr_type == ADDR_IPV4 ? address4 : address6);
    }

    return new_socket;
}

bool valid_user_and_password(char* user, char* pass) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (socks5_args.users[i].name[0] != 0 && strcmp(user, socks5_args.users[i].name) == 0 && strcmp(pass, socks5_args.users[i].pass) == 0) {
            return true;
        }
    }
    return false;
}

bool valid_user_is_registered(char* user) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (socks5_args.users[i].name[0] != 0 && strcmp(user, socks5_args.users[i].name) == 0) {
            return true;
        }
    }
    return false;
}

bool server_check_if_full() {
    return socks5_args.nusers == MAX_USERS;
}

void add_user(char* user, char* pass) {
    bool done = false;
    for (int i = 0; i < MAX_USERS && done == false; i++) {
        if (socks5_args.users[i].name[0] == 0) {
            char* usern = socks5_args.users[i].name;
            char* passw = socks5_args.users[i].pass;
            strcpy(usern, user);
            strcpy(passw, pass);
            socks5_args.nusers++;
            done = true;
        }
    }
}

void delete_user(char* user) {
    bool flag = true;
    for (int i = 0; i < MAX_USERS && flag; i++) {
        if (socks5_args.users[i].name[0] != 0 && strcmp(user, socks5_args.users[i].name) == 0) {
            socks5_args.nusers--;
            socks5_args.users[i].pass[0] = 0;
            socks5_args.users[i].name[0] = 0;
            flag = false;
        }
    }
}

bool isNumber(char* s) {
    for (int i = 0; s[i] != '\0'; i++) {
        if (isdigit(s[i]) == 0)
            return false;
    }
    return true;
}