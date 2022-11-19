#ifndef __AUTH_H_
#define __AUTH_H_

#include "buffer.h"
#include <stdbool.h>
#include <stdint.h>

#define MAX_LEN_USERS 64
#define AUTH_SUCCESS 0x00
#define AUTH_FAIL 0x01
#define AUTH_VERSION_VALUE 0x01

#define AUTH_RESPONSE_LEN 2

/* Once the SOCKS V5 server has started, and the client has selected the
   Username/Password Authentication protocol (0x02 --> METHOD_AUTHENTICATION in hello.h),
   the Username/Password subnegotiation begins. This begins with the client producing
   a Username/Password request:

           +----+------+----------+------+----------+
           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +----+------+----------+------+----------+
           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
           +----+------+----------+------+----------+

   ** VER contains the current version of the subnegotiation which is X'01'.
   ** ULEN contains the length of the UNAME field that follows.
   ** UNAM  contains the username as known to the source OS.
   ** PLEN contains the length of the PASSWD field that follows.
   ** PASSWD contains the password association with the given UNAME.

   The server verifies the supplied UNAME and PASSWD, and sends the
   following response:

                        +-----+--------+
                        | VER | STATUS |
                        +-----+--------+
                        |  1  |   1    |
                        +-----+--------+

   A STATUS field of X'00' indicates success. If the server returns a
   `failure' (STATUS value other than X'00') status, it MUST close the
   connection.
*/

typedef enum auth_state {
    AUTH_VERSION,
    AUTH_USERNAME_LEN,
    AUTH_USERNAME,
    AUTH_PASSWORD_LEN,
    AUTH_PASSWORD,
    AUTH_DONE,
    AUTH_ERROR,
} auth_state;

typedef enum auth_status {
    AUTH_VALID,
    AUTH_INVALID_VERSION,
    AUTH_INVALID_USERNAME_LEN,
    AUTH_INVALID_PASSWORD_LEN,
} auth_status;

typedef struct auth_parser {
    uint8_t version;
    auth_state state;
    auth_status status;

    uint8_t user_len;
    char username[MAX_LEN_USERS];
    uint8_t pass_len;
    char password[MAX_LEN_USERS];

    uint8_t credentials;
} auth_parser;

/** Inicializa el parser */
void auth_parser_init(struct auth_parser* p);

/** Entrega un byte al parser. Retorna true si se llego al final  */
enum auth_state auth_parser_feed(struct auth_parser* p, const uint8_t b);

/**
 * Por cada elemento del buffer llama a 'auth_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 */
bool auth_parser_consume(buffer* buffer, struct auth_parser* p, bool* errored);

/**
 * Permite distinguir a quien usa 'auth_parser_feed' si debe seguir
 * enviando caracters o no.
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool auth_parser_is_done(enum auth_state state, bool* errored);

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
char* auth_parser_error(struct auth_parser* p);

void auth_parser_close(struct auth_parser* p);

/**
 * Serializa en buff la respuesta al request.
 * Retorna la cantidad de bytes ocupados del buffer o -1 si no había espacio suficiente.
 */
int auth_parser_marshall(buffer* b, const uint8_t status, uint8_t version);

#endif
