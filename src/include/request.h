#ifndef Au9MTAsFSOTIW3GaVruXIl3gVBU_REQUEST_H
#define Au9MTAsFSOTIW3GaVruXIl3gVBU_REQUEST_H

#include "buffer.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#define IPV4_LEN 4
#define IPV6_LEN 16
#define PORT_LEN 2
#define DEFAULT_REQUEST_LEN 6
#define SOCKS5_VERSION 0x05

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

/** Comando validos */
enum socks5_req_cmd {
    SOCKS5_REQ_CMD_CONNECT = 0x01,
    SOCKS5_REQ_CMD_BIND = 0x02,
    SOCKS5_REQ_CMD_ASSOCIATE = 0x03,
};

/** Tipos de direcciones validos */
enum socks5_addr_type {
    SOCKS5_REQ_ADDRTYPE_IPV4 = 0x01,
    SOCKS5_REQ_ADDRTYPE_DOMAIN = 0x03,
    SOCKS5_REQ_ADDRTYPE_IPV6 = 0x04,
};

union socks5_addr {
    char fqdn[0xff];
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
};

typedef struct request {
    enum socks5_req_cmd cmd;
    enum socks5_addr_type dest_addr_type;
    union socks5_addr dest_addr;
    in_port_t dest_port; // Port in network byte order
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

/**
 * @brief Inicializa el parser
 */
void request_parser_init(struct request_parser* p);

/**
 * @brief Entrega un byte al parser. Retorna true si se llego al final
 */
enum request_state request_parser_feed(struct request_parser* p, const uint8_t b);

/**
 * @brief Por cada elemento del buffer llama a 'request_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 */
enum request_state request_parser_consume(buffer* b, struct request_parser* p, bool* errored);

/**
 * @brief Permite distinguir a quien usa 'request_parser_feed' si debe seguir
 * enviando caracters o no.
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool request_parser_is_done(enum request_state st, bool* errored);

/**
 * @brief En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
char* request_parser_error(struct request_parser* p);

/**
 * @brief Libera recursos internos del parser
 */
void request_parser_close(struct request_parser* p);

/**
 * @brief Serializa en buff la respuesta al request.

 * @return Retorna la cantidad de bytes ocupados del buffer o -1 si no había espacio suficiente.
 */
int request_parser_marshall(buffer* b, const enum socks5_response_status status, const enum socks5_addr_type atyp, const union socks5_addr dest_addr, const in_port_t dest_port);

/**
 * @brief Convierte a errno en socks5_response_status
 */
enum socks5_response_status errno_to_socks(int e);

/**
 * @brief Se encarga de la resolución de un request
 */
enum socks5_response_status cmd_resolve(struct request* request, struct sockaddr** originaddr, socklen_t* originlen, int* domain);

#endif
