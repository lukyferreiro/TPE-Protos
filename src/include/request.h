#ifndef Au9MTAsFSOTIW3GaVruXIl3gVBU_REQUEST_H
#define Au9MTAsFSOTIW3GaVruXIl3gVBU_REQUEST_H

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"

/*   The SOCKS request is formed as follows:
 *
 *      +----+-----+-------+------+----------+----------+
 *      |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *      +----+-----+-------+------+----------+----------+
 *      | 1  |  1  | X'00' |  1   | Variable |    2     |
 *      +----+-----+-------+------+----------+----------+
 *
 *   Where:
 *
 *        o  VER    protocol version: X'05'
 *        o  CMD
 *           o  CONNECT X'01'
 *           o  BIND X'02'
 *           o  UDP ASSOCIATE X'03'
 *        o  RSV    RESERVED
 *        o  ATYP   address type of following address
 *           o  IP V4 address: X'01'
 *           o  DOMAINNAME: X'03'
 *           o  IP V6 address: X'04'
 *        o  DST.ADDR       desired destination address
 *        o  DST.PORT desired destination port in network octet
 *           order
 */

/*
 * Miembros de la sección 4: `Requests'
 *  - Cmd
 *  - AddressType
 *  - Address: IPAddress (4 y 6), DomainNameAdddres
 */

/** Comando validos */
enum socks_req_cmd {
    SOCKS5_REQ_CMD_CONNECT = 0x01,
    SOCKS5_REQ_CMD_BIND = 0x02,
    SOCKS5_REQ_CMD_ASSOCIATE = 0x03,
};

/** Tipos de direcciones validos */
enum socks_addr_type {
    SOCKS5_REQ_ADDRTYPE_IPV4 = 0x01,
    SOCKS5_REQ_ADDRTYPE_DOMAIN = 0x03,
    SOCKS5_REQ_ADDRTYPE_IPV6 = 0x04,
};

union socks_addr {
    char fqdn[0xff];
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
};

typedef struct request {
    enum socks_req_cmd cmd;
    enum socks_addr_type dest_addr_type;
    union socks_addr dest_addr;
    /** Port in network byte order */
    in_port_t dest_port;
} request;

enum request_state {
    REQUEST_VERSION,
    REQUEST_CMD,
    REQUEST_RSV,
    REQUEST_ATYP,
    REQUEST_DSTADDR_FQDN,
    REQUEST_DSTADDR,
    REQUEST_DSTPORT,

    // A partir de aca están done
    REQUEST_DONE,

    // Y a partir de aca son considerado con error
    REQUEST_ERROR,
    REQUEST_ERROR_UNSUPPORTED_VERSION,
    REQUEST_ERROR_UNSUPPORTED_ATYP,
};

typedef struct request_parser {
    struct request* request;
    enum request_state state;
    uint8_t totalBytesToRead; // Cuantos bytes tenemos que leer
    uint8_t readBytes;        // Cuantos bytes ya leimos
} request_parser;

enum socks5_response_status {
    SOCKS5_STATUS_SUCCEED = 0x00,
    SOCKS5_STATUS_GENERAL_SERVER_FAILURE = 0x01,
    SOCKS5_STATUS_CONN_NOT_ALLOWED_BY_RULESET = 0x02,
    SOCKS5_STATUS_NETWORK_UNREACHABLE = 0x03,
    SOCKS5_STATUS_HOST_UNREACHABLE = 0x04,
    SOCKS5_STATUS_CONNECTION_REFUSED = 0x05,
    SOCKS5_STATUS_TTL_EXPIRED = 0x06,
    SOCKS5_STATUS_COMMAND_NOT_SUPPORTED = 0x07,
    SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
};

/** Inicializa el parser */
void request_parser_init(struct request_parser* p);

/** Entrega un byte al parser. retorna true si se llego al final  */
enum request_state request_parser_feed(struct request_parser* p, const uint8_t c);

/**
 * Por cada elemento del buffer llama a `request_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum request_state request_parser_consume(buffer* b, struct request_parser* p, bool* errored);

/**
 * Permite distinguir a quien usa socks_hello_parser_feed si debe seguir
 * enviando caracters o no.
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool request_parser_is_done(const enum request_state st, bool* errored);

void request_parser_close(struct request_parser* p);

/**
 * Serializa en buff la una respuesta al request.
 *
 * Retorna la cantidad de bytes ocupados del buffer o -1 si no había
 * espacio suficiente.
 */
extern int request_parser_marshall(buffer* b, const enum socks5_response_status status);

/** Convierte a errno en socks5_response_status */
enum socks5_response_status errno_to_socks(int e);

/** Se encarga de la resolcuión de un request */
enum socks5_response_status cmd_resolve(struct request* request, struct sockaddr** originaddr,
                                       socklen_t* originlen, int* domain);

#endif
