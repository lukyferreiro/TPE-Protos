#ifndef __HELLO_H_
#define __HELLO_H_

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"

static const uint8_t METHOD_NO_AUTHENTICATION_REQUIRED = 0x00;
static const uint8_t METHOD_AUTHENTICATION = 0x02;
static const uint8_t METHOD_NO_ACCEPTABLE_METHODS = 0xFF;

/*
 *   The client connects to the server, and sends a version
 * identifier/method selection message:
 *
 *                 +----+----------+----------+
 *                 |VER | NMETHODS | METHODS  |
 *                 +----+----------+----------+
 *                 | 1  |    1     | 1 to 255 |
 *                 +----+----------+----------+
 *
 *  The VER field is set to X'05' for this version of the protocol.  The
 *  NMETHODS field contains the number of method identifier octets that
 *  appear in the METHODS field.
 */

/** Estado del parser de hello request */
enum hello_state {
    HELLO_VERSION,
    HELLO_NMETHODS,     // Debemos leer la cantidad de metodos
    HELLO_METHODS,      // Nos encontramos leyendo los métodos
    HELLO_DONE,
    HELLO_ERROR_UNSUPPORTED_VERSION,
};

typedef struct hello_parser {
    /** Invocado cada vez que se presenta un nuevo método */
    void (*on_authentication_method)(struct hello_parser* parser, uint8_t method);
    void* data;             // Permite al usuario del parser almacenar sus datos
    enum hello_state state;
    uint8_t remaining;      // Metodos que faltan por leer
} hello_parser;

/**
 * @brief Inicializa el parser
 */
void hello_parser_init(struct hello_parser* p, void (*on_authentication_method)(hello_parser *p, uint8_t method));

/**
 * @brief Entrega un byte al parser. retorna true si se llego al final 
 */
enum hello_state hello_parser_feed(struct hello_parser* p, const uint8_t b);

/**
 * @brief Por cada elemento del buffer llama a 'hello_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 */
enum hello_state hello_parser_consume(buffer* b, struct hello_parser* p, bool* errored);

/**
 * @brief Permite distinguir a quien usa 'hello_parser_feed' si debe seguir
 * enviando caracters o no.
 */
bool hello_parser_is_done(enum hello_state state, bool* errored);

/**
 * @brief En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
char* hello_parser_error(struct hello_parser* p);

/**
 * @brief Libera recursos internos del parser
 */
void hello_parser_close(struct hello_parser* p);

/**
 * @brief Serializa en buff la una respuesta al hello.
 * 
 * @return Retorna la cantidad de bytes ocupados del buffer o -1 si no había espacio suficiente. 
 */
int hello_parser_marshall(buffer* b, const uint8_t method);

#endif
