#ifndef NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U
#define NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U

#include <netinet/in.h>

#include "buffer.h"

typedef enum addr_type {
    ADDR_IPV4,
    ADDR_IPV6,
    ADDR_DOMAIN,
} addr_type;

#define SOCKADDR_TO_HUMAN_MIN (INET6_ADDRSTRLEN + 5 + 1)

/**
 * Describe de forma humana un sockaddr:
 *
 * @param buff     el buffer de escritura
 * @param buffsize el tamaño del buffer  de escritura
 *
 * @param af    address family
 * @param addr  la dirección en si
 * @param nport puerto en network byte order
 *
 */
const char* sockaddr_to_human(char* buff, const size_t buffsize, const struct sockaddr* addr);

/**
 * Escribe n bytes de buff en fd de forma bloqueante
 * Retorna 0 si se realizó sin problema y errno si hubo problemas
 */
int sock_blocking_write(const int fd, buffer* b);

/**
 * Copia todo el contenido de source a dest de forma bloqueante.
 * Retorna 0 si se realizó sin problema y errno si hubo problemas
 */
int sock_blocking_copy(const int source, const int dest);

#endif
