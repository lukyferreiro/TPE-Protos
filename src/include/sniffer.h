#ifndef __SNIFFER_H_
#define __SNIFFER_H_

// https://www.rfc-es.org/rfc/rfc1939-es.txt

#include "buffer.h"
#include "logger.h"
#include <stdint.h>

#define MAX_LEN_USERS 64
#define RAW_BUFF_SNIFFER_SIZE 4096 // for CRLF  Especifica que la longitud de un indicador de estado está limitada a 512 octetos, incluyendo el CRLF quote rfc 1939.

#define N(x) (sizeof(x) / sizeof((x)[0]))

typedef enum sniffer_state {
    SNIFFER_OK,
    SNIFFER_USER,
    SNIFFER_READ_USER,
    SNIFFER_PASS,
    SNIFFER_READ_PASS,
    SNIFFER_CHECK_OK,
    SNIFFER_SUCCESS,
    SNIFFER_ERROR
} sniffer_state;

typedef struct sniffer_parser {
    sniffer_state state;
    bool is_initiated;
    buffer buffer;
    uint8_t raw_buff[RAW_BUFF_SNIFFER_SIZE];
    char username[MAX_LEN_USERS];
    char password[MAX_LEN_USERS];
    uint16_t bytes_remaining;
    uint16_t bytes_read;
} sniffer_parser;

/** Inicializa el parser */
void sniffer_parser_init(sniffer_parser* p);

/** Entrega un byte al parser. retorna true si se llego al final  */
enum sniffer_state sniffer_parser_feed(sniffer_parser* p, const uint8_t b);

/**
 * Por cada elemento del buffer llama a 'sniffer_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 */
enum sniffer_state sniffer_parser_consume(struct sniffer_parser* p);

/**
 * Permite distinguir a quien usa 'sniffer_parser_feed' si debe seguir
 * enviando caracters o no.
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool sniffer_parser_is_done(struct sniffer_parser* p);

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
char* sniffer_parser_error(struct sniffer_parser* p);

/** Libera recursos internos del parser */
void sniffer_parser_close(struct sniffer_parser* p);

#endif