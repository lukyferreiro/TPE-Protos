#ifndef SNIFFER_H
#define SNIFFER_H

// https://www.rfc-es.org/rfc/rfc1939-es.txt

#include <stdint.h>
#include "buffer.h"
#include "logger.h"

#define MAX_LEN_USERS 64
#define RAW_BUFF_SNIFFER_SIZE 4096 // for CRLF       - especifica que la longitud de un indicador de estado está limitada a
                                   //512 octetos, incluyendo el CRLF quote rfc 1939.

#define N(x) (sizeof(x) / sizeof((x)[0]))

             typedef enum sniffer_state {
                 SNIFFER_OK,
                 SNIFFER_USER,
                 SNIFFER_READ_USER,
                 SNIFFER_PASS,
                 SNIFFER_READ_PASS,
                 SNIFFER_CHECK_OK,
                 SNIFFER_TRAP,
                 SNIFFER_SUCCESS
             } sniffer_state;

             
typedef struct sniffer_parser
{
    sniffer_state state;
    bool is_initiated;
    buffer buffer;
    uint8_t raw_buff[RAW_BUFF_SNIFFER_SIZE];
    char username[MAX_LEN_USERS];
    char password[MAX_LEN_USERS]; // credentials to sniff
    uint16_t bytes_remaining;
    uint16_t bytes_read;
} sniffer_parser;

void sniffer_parser_init(sniffer_parser *p);

enum sniffer_state sniffer_parser_feed(sniffer_parser *p, const uint8_t b);

bool sniffer_parser_is_done(struct sniffer_parser *p);

enum sniffer_state sniffer_parser_consume(struct sniffer_parser *p);

#endif