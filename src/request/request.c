// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "request.h"
#include "logger.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h> // memset

static void remaining_set(struct request_parser* p, const int n) {
    p->readBytes = 0;
    p->totalBytesToRead = n;
}

static int remaining_is_done(struct request_parser* p) {
    return p->readBytes >= p->totalBytesToRead;
}

static enum request_state version(const uint8_t c, struct request_parser* p) {
    enum request_state next;
    switch (c) {
        case SOCKS5_VERSION: // Version 5 de socks
            next = REQUEST_CMD;
            break;
        default:
            next = REQUEST_ERROR_UNSUPPORTED_VERSION;
            break;
    }

    return next;
}

static enum request_state cmd(const uint8_t c, struct request_parser* p) {
    p->request->cmd = c;
    return REQUEST_RSV;
}

static enum request_state rsv(const uint8_t c, struct request_parser* p) {
    return REQUEST_ATYP;
}

static enum request_state atyp(const uint8_t c, struct request_parser* p) {
    enum request_state next;
    p->request->dest_addr_type = c;

    switch (p->request->dest_addr_type) {
        case SOCKS5_REQ_ADDRTYPE_IPV4:
            remaining_set(p, IPV4_LEN); // Longitud de IPv4
            memset(&(p->request->dest_addr.ipv4), 0, sizeof(p->request->dest_addr.ipv4));
            p->request->dest_addr.ipv4.sin_family = AF_INET;
            next = REQUEST_DSTADDR;
            break;
        case SOCKS5_REQ_ADDRTYPE_IPV6:
            remaining_set(p, IPV6_LEN); // Longitud de IPv6
            memset(&(p->request->dest_addr.ipv6), 0, sizeof(p->request->dest_addr.ipv6));
            p->request->dest_addr.ipv6.sin6_family = AF_INET6;
            next = REQUEST_DSTADDR;
            break;
        case SOCKS5_REQ_ADDRTYPE_DOMAIN:
            next = REQUEST_DSTADDR_FQDN;
            break;
        default:
            next = REQUEST_ERROR_UNSUPPORTED_ATYP;
            break;
    }

    return next;
}

static enum request_state dstaddr_fqdn(const uint8_t c, struct request_parser* p) {
    remaining_set(p, c);
    p->request->dest_addr.fqdn[p->totalBytesToRead - 1] = 0;
    return REQUEST_DSTADDR;
}

static enum request_state dstaddr(const uint8_t c, struct request_parser* p) {
    enum request_state next;

    switch (p->request->dest_addr_type) {
        case SOCKS5_REQ_ADDRTYPE_IPV4:
            p->request->dest_addr.ipv4.sin_addr.s_addr = (p->request->dest_addr.ipv4.sin_addr.s_addr << 8) + c;
            p->readBytes++;
            // Cuando termino de leer la IP, le paso el puerto
            if (remaining_is_done(p)) {
                p->request->dest_addr.ipv4.sin_addr.s_addr = htonl(p->request->dest_addr.ipv4.sin_addr.s_addr);
            }
            break;
        case SOCKS5_REQ_ADDRTYPE_IPV6:
            ((uint8_t*)&(p->request->dest_addr.ipv6.sin6_addr))[p->readBytes++] = c;
            break;
        case SOCKS5_REQ_ADDRTYPE_DOMAIN:
            p->request->dest_addr.fqdn[p->readBytes++] = c;
            break;
        default:
            //next = REQUEST_ERROR_UNSUPPORTED_ATYP;
            break;
    }
    // Cuando termino la lectura
    if (remaining_is_done(p)) {
        remaining_set(p, PORT_LEN); // Longitud del port
        p->request->dest_port = 0;
        next = REQUEST_DSTPORT;
    } else {
        next = REQUEST_DSTADDR;
    }

    return next;
}

static enum request_state dstport(const uint8_t c, struct request_parser* p) {
    enum request_state next = REQUEST_DSTPORT;
    *(((uint8_t*)&(p->request->dest_port)) + p->readBytes) = c;
    p->readBytes++;
    if (remaining_is_done(p)) {
        next = REQUEST_DONE;
    }
    return next;
}

void request_parser_init(struct request_parser* p) {
    p->state = REQUEST_VERSION;
}

enum request_state request_parser_feed(struct request_parser* p, const uint8_t b) {
    switch (p->state) {
        //Segun el estado en el que me encuentre, paso al siguiente
        case REQUEST_VERSION:
            p->state = version(b, p);
            break;
        case REQUEST_CMD:
            p->state = cmd(b, p);
            break;
        case REQUEST_RSV:
            p->state = rsv(b, p);
            break;
        case REQUEST_ATYP:
            p->state = atyp(b, p);
            break;
        case REQUEST_DSTADDR_FQDN:
            p->state = dstaddr_fqdn(b, p);
            break;
        case REQUEST_DSTADDR:
            p->state = dstaddr(b, p);
            break;
        case REQUEST_DSTPORT:
            p->state = dstport(b, p);
            break;
        case REQUEST_DONE:
        case REQUEST_ERROR:
        case REQUEST_ERROR_UNSUPPORTED_VERSION:
        case REQUEST_ERROR_UNSUPPORTED_ATYP:
            // Nada para hacer
            break;
        default:
            logger(DEBUG, "Unknown state on request parser");
            abort();
            break;
    }

    return p->state;
}

enum request_state request_parser_consume(buffer* b, struct request_parser* p, bool* errored) {
    while (!request_parser_is_done(p->state, errored) && buffer_can_read(b)) {
        uint8_t byte = buffer_read(b);
        p->state = request_parser_feed(p, byte);
    }

    return request_parser_is_done(p->state, errored);
}

bool request_parser_is_done(enum request_state st, bool* errored) {
    if (errored != NULL) {
        *errored = false;
    }
    switch (st) {
        case REQUEST_DONE:
            return true;
            break;

        case REQUEST_VERSION:
        case REQUEST_CMD:
        case REQUEST_RSV:
        case REQUEST_ATYP:
        case REQUEST_DSTADDR_FQDN:
        case REQUEST_DSTADDR:
        case REQUEST_DSTPORT:
            return false;
            break;

        case REQUEST_ERROR_UNSUPPORTED_VERSION:
        case REQUEST_ERROR_UNSUPPORTED_ATYP:
        case REQUEST_ERROR:
        default:
            if (errored != NULL) {
                *errored = true;
            }
            return true;
            break;
    }
}

char* request_parser_error(struct request_parser* p) {
    switch (p->state) {
        case REQUEST_DONE:
        case REQUEST_VERSION:
        case REQUEST_CMD:
        case REQUEST_RSV:
        case REQUEST_ATYP:
        case REQUEST_DSTADDR_FQDN:
        case REQUEST_DSTADDR:
        case REQUEST_DSTPORT:
            return "[REQUEST_PARSER] No error";
            break;
        case REQUEST_ERROR_UNSUPPORTED_VERSION:
            return "[REQUEST_PARSER] Unsupported version";
            break;
        case REQUEST_ERROR_UNSUPPORTED_ATYP:
            return "[REQUEST_PARSER] Unsupported address type";
            break;
        default:
            return "[REQUEST_PARSER] Unknown error";
            break;
    }
}

void request_parser_close(struct request_parser* p) {
    // Nada que hacer
}

int request_parser_marshall(buffer* b, const enum socks5_response_status status,
                            const enum socks5_addr_type atyp,
                            const union socks5_addr dest_addr,
                            const in_port_t dest_port) {
    size_t n;
    size_t request_len = DEFAULT_REQUEST_LEN;
    int dest_addr_size = 0;
    uint8_t* aux_dest_addr = NULL;
    uint8_t* buff = buffer_write_ptr(b, &n);

    switch (atyp) {
        case SOCKS5_REQ_ADDRTYPE_IPV4:
            dest_addr_size = IPV4_LEN;
            request_len += dest_addr_size;
            aux_dest_addr = (uint8_t*)malloc(dest_addr_size * sizeof(uint8_t));
            memcpy(aux_dest_addr, &dest_addr.ipv4.sin_addr, dest_addr_size);
            break;

        case SOCKS5_REQ_ADDRTYPE_IPV6:
            dest_addr_size = IPV6_LEN;
            request_len += dest_addr_size;
            aux_dest_addr = (uint8_t*)malloc(dest_addr_size * sizeof(uint8_t));
            memcpy(aux_dest_addr, &dest_addr.ipv6.sin6_addr, dest_addr_size);
            break;

        case SOCKS5_REQ_ADDRTYPE_DOMAIN:
            dest_addr_size = strlen(dest_addr.fqdn);
            aux_dest_addr = (uint8_t*)malloc((dest_addr_size + 1) * sizeof(uint8_t));
            aux_dest_addr[0] = dest_addr_size;
            memcpy(aux_dest_addr + 1, dest_addr.fqdn, dest_addr_size);
            dest_addr_size++;
            request_len += dest_addr_size;
            break;
        default:
            logger(LOG_ERROR, "Invalid ATYP in request_parser_marshall");
            return -1;
            break;
    }

    if (n < request_len) {
        free(aux_dest_addr);
        return -1;
    }

    buff[0] = SOCKS5_VERSION;
    buff[1] = status;
    buff[2] = 0x00;
    buff[3] = atyp;
    memcpy(&buff[4], aux_dest_addr, dest_addr_size);
    memcpy(&buff[4 + dest_addr_size], &dest_port, 2);
    free(aux_dest_addr);
    buffer_write_adv(b, request_len);
    return request_len;
}

enum socks5_response_status errno_to_socks(const int e) {
    enum socks5_response_status ret = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
    switch (e) {
        case 0:
            ret = SOCKS5_STATUS_SUCCEED;
            break;
        case ECONNREFUSED:
            ret = SOCKS5_STATUS_CONNECTION_REFUSED;
            break;
        case EHOSTUNREACH:
            ret = SOCKS5_STATUS_HOST_UNREACHABLE;
            break;
        case ENETUNREACH:
            ret = SOCKS5_STATUS_NETWORK_UNREACHABLE;
            break;
        case ETIMEDOUT:
            ret = SOCKS5_STATUS_TTL_EXPIRED;
            break;
    }
    return ret;
}

enum socks5_response_status cmd_resolve(struct request* request, struct sockaddr** originaddr,
                                        socklen_t* originlen, int* domain) {
    enum socks5_response_status ret = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
    *domain = AF_INET;
    struct sockaddr* addr = 0x00;
    socklen_t addrlen = 0;

    switch (request->dest_addr_type) {
        // En caso de tener una IPv4
        case SOCKS5_REQ_ADDRTYPE_IPV4: {
            //*domain = AF_INET;
            addr = (struct sockaddr*)&(request->dest_addr.ipv4);
            addrlen = sizeof(request->dest_addr.ipv4);
            request->dest_addr.ipv4.sin_port = request->dest_port;
            break;
        }
        // En caso de tener una IPv6
        case SOCKS5_REQ_ADDRTYPE_IPV6: {
            *domain = AF_INET6;
            addr = (struct sockaddr*)&(request->dest_addr.ipv6);
            addrlen = sizeof(request->dest_addr.ipv6);
            request->dest_addr.ipv6.sin6_port = request->dest_port;
            break;
        }
        // En caso de tener un FQDN
        case SOCKS5_REQ_ADDRTYPE_DOMAIN: {
            struct hostent* hp = gethostbyname(request->dest_addr.fqdn);
            if (hp == 0) {
                memset(&request->dest_addr, 0x00, sizeof(request->dest_addr));
                break;
            }
            request->dest_addr.ipv4.sin_family = hp->h_addrtype;
            memcpy((char*)&request->dest_addr.ipv4.sin_addr, *hp->h_addr_list, hp->h_length);
        }
        default:
            return SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED;
    }

    *originaddr = addr;
    *originlen = addrlen;

    return ret;
}