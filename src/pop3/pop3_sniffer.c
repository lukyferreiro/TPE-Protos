#include "pop3_sniffer.h"
#include <ctype.h>
#include <string.h>

// based on  www.rfc-es.org/rfc/rfc1939-es.txt

static const char *OK = "+OK";
static const char *USER = "USER ";
static const char *PASS = "PASS ";
static const char *ERR = "-ERR";

void pop3_sniffer_parser_init(pop3_sniffer_parser *p){
    buffer_init(&p->buffer, N(p->raw_buff), p->raw_buff);
    p->current_state = POP3_OK;
    p->read_bytes = 0;
    p->remaining_bytes = strlen(OK);
    p->is_initiated = true;
}

static enum pop3_sniffer_state ok_message(struct pop3_sniffer_parser *p,
                                          uint8_t b)
{
    if (tolower(b) == tolower(*(OK + p->bytes_read)))
    {
        p->bytes_read++;
        p->bytes_remaining--;
        if (p->bytes_remaining == 0)
        {
            p->bytes_read = 0;
            p->bytes_remaining = strlen("USER ");
            return POP3_USER;
        }
    }
    else
    {
        return POP3_TRAP;
    }
    return POP3_OK;
}

enum pop3_sniffer_state user_message(struct pop3_sniffer_parser *p,
                                     uint8_t b)
{
    if (tolower(b) == tolower(*(USER + p->bytes_read)))
    {
        p->bytes_reads++;
        p->remaining_bytes--;
        if (p -> bytes_remaining == 0)
        {
            p->bytes_read = 0;
            return POP3_READ_USER;
        }
    }
    else if (p->bytes_read != 0)
    {
        p->bytes_read = 0;
        p->bytes_remaining = strlen(USER);
    }
    return POP3_USER;
}

bool pop3_sniffer_parser_is_done(struct pop3_sniffer_parser *p)
{
    return p->state == POP3_SUCCESS;
}

enum pop3_sniffer_state
pop3_sniffer_parser_consume(struct pop3_sniffer_parser *p,){
    while (buffer_can_read(&p->buffer) && !pop3_sniffer_parser_is_done(p))
    {
        uint8_t byte = buffer_read(&p->buffer);
        p->current_state = pop3_sniffer_parser_feed(p, byte);
    }

    if (p->current_state == POP3_SUCCESS)
    {
      // print con el logger?
    }

    return p->current_state;
}

enum pop3_sniffer_state pop3_sniffer_parser_feed(pop3_sniffer_parser *p,
                                                 const uint8_t byte)
{
    switch (p->current_state)
    {  //TODO 
    }
}