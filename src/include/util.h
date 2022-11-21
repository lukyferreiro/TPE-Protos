#ifndef UTIL_H_
#define UTIL_H_

#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>

const char* printFamily(struct addrinfo* aip);
const char* printType(struct addrinfo* aip);
const char* printProtocol(struct addrinfo* aip);
const char* printFlags(struct addrinfo* aip);
const char* printAddressPort(const struct addrinfo* aip, struct sockaddr* address);
const char* printSocketAddress(const struct sockaddr* address);

// Determina si dos sockets son iguales (misma direccion y puerto)
int sockAddrsEqual(const struct sockaddr* addr1, const struct sockaddr* addr2);

#endif