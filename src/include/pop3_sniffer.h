#ifndef POP3_SNIFFER_H
#define POP3_SNIFFER_H

// https://www.rfc-es.org/rfc/rfc1939-es.txt

#include <stdint.h>
#include "buffer.h"
#include "logger.h"

#define CREDENTIALS_MAX_LENGTH 256
#define RAW_BUFF_POP3_SIZE 4096  //for CRLF

#define N(x) (sizeof(x) / sizeof((x)[0]))

typedef enum pop3_sniffer_state
{
    POP3_OK,
    POP3_USER,
    POP3_READ_USER,
    POP3_PASS,
    POP3_READ_PASS,
    POP3_CHECK_OK,
    POP3_TRAP,
    POP3_SUCCESS
} pop3_sniffer_state;

typedef struct pop3_sniffer_parser
{
    pop3_sniffer_state state;
    bool is_initiated;
    buffer buffer;
    uint8_t raw_buff[RAW_BUFF_POP3_SIZE];
    char username[CREDENTIALS_MAX_LENGTH];
    char password[CREDENTIALS_MAX_LENGTH];      // credentials to sniff
    uint16_t bytes_remaining;
    uint16_t bytes_read;
} pop3_sniffer_parser;

void pop3_sniffer_parser_init(pop3_sniffer_parser *p);

enum pop3_sniffer_state pop3_sniffer_parser_feed(pop3_sniffer_parser *p, const uint8_t b);

bool pop3_sniffer_parser_is_done(struct pop3_sniffer_parser *p);

enum pop3_sniffer_state pop3_sniffer_parser_consume(struct pop3_sniffer_parser *p);

#endif