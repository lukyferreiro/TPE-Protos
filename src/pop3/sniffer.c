#include "sniffer.h"
#include <ctype.h>
#include <string.h>

// based on  www.rfc-es.org/rfc/rfc1939-es.txt

static const char *OK = "+OK";
static const char *USER = "USER ";  //respuestas establecidas por el rfc
static const char *PASS = "PASS ";
static const char *ERR = "-ERR";

void sniffer_parser_init(sniffer_parser *p){
    buffer_init(&p->buffer, N(p->raw_buff), p->raw_buff);
    p->current_state = SNIFFER_OK;
    p->read_bytes = 0;
    p->remaining_bytes = strlen(OK);
    p->is_initiated = true;
}


enum sniffer_state user_message(struct sniffer_parser *p,uint8_t b){
    if (tolower(b) == tolower(*(USER + p->bytes_read)))
    {
        p->bytes_read++;
        p->remaining_bytes--;
        if (p -> bytes_remaining == 0)
        {
            p->bytes_read = 0;
            return SNIFFER_READ_USER;
        }
    }
    else if (p->bytes_read != 0)
    {
        p->bytes_read = 0;
        p->bytes_remaining = strlen(USER);
    }
    return SNIFFER_USER;
}

enum sniffer_state pass_message(struct sniffer_parser *p,uint8_t b){
    if (tolower(b) == tolower(*(PASS + p->read_bytes)))   //rfc 1939
    {
        p->bytes_read++;
        p->bytes_remaining--;
        if (p->bytes_remaining == 0)
        {
            p->bytes_read = 0;
            return SNIFFER_READ_PASS;
        }
    }
    else if (p->bytes_read != 0)
    {
        p->bytes_read = 0;
        p->bytes_remaining = strlen(PASS);
    }
    return SNIFFER_PASS;
}

enum sniffer_state read_username(struct sniffer_parser *p, uint8_t b){
    if (b != '\n')
    {
        if (p->bytes_read < MAX_LEN_USERS)
        {
            p->username[p->bytes_read++] = b;
        }
    }
    else
    {
        p->username[p->bytes_read] = '\0';
        p->bytes_read = 0;
        p->bytes_remaining = strlen(PASS);
        return SNIFFER_PASS;
    }
    return SNIFFER_READ_USER;
}

enum sniffer_state read_password(struct sniffer_parser *p,uint8_t b){
    if (b != '\n')
    {
        if (p->bytes_read < MAX_LEN_USERS)
        {
            p->password[p->bytes_read++] = b;
        }
    }
    else
    {
        p->password[p->bytes_read] = '\0';
        p->bytes_read = 0;
        return SNIFFER_CHECK_OK;
    }
    return SNIFFER_READ_PASS;
}

bool sniffer_parser_is_done(struct sniffer_parser *p){
    return p->state == SNIFFER_SUCCESS;
}

static enum sniffer_state ok_message(struct sniffer_parser *p, uint8_t b){
    if (tolower(b) == tolower(*(OK + p->bytes_read)))
    {
        p->bytes_read++;
        p->bytes_remaining--;
        if (p->bytes_remaining == 0)
        {
            p->bytes_read = 0;
            p->bytes_remaining = strlen("USER ");
            return SNIFFER_USER;
        }
    }
    else
    {
        return SNIFFER_TRAP;
    }
    return SNIFFER_OK;
}

enum sniffer_state sniffer_parser_consume(struct sniffer_parser *p,){
    while (buffer_can_read(&p->buffer) && !sniffer_parser_is_done(p))
    {
        uint8_t byte = buffer_read(&p->buffer);
        p->current_state = sniffer_parser_feed(p, byte);
    }

    if (p->current_state == SNIFFER_SUCCESS)
    {
        log(INFO, p->username);
        log(INFO, p->password);
    }

    return p->current_state;
}

enum sniffer_state sniffer_parser_feed(sniffer_parser *p,const uint8_t b){
    switch (p->state)
    {
    case SNIFFER_OK:
        p->current_state = ok_message(p, b);
        break;

    case SNIFFER_USER:
        p->current_state = user_message(p, b);
        break;

    case SNIFFER_READ_USER:
        p->current_state = read_username(p, b);
        break;

    case SNIFFER_PASS:
        p->current_state = pass_message(p, b);
        ;
        break;

    case SNIFFER_READ_PASS:
        p->current_state = read_password(p, b);
        break;

    case SNIFFER_CHECK_OK:
        p->current_state = check_ok(p, b);
        break;

    case SNIFFER_TRAP:
    case SNIFFER_SUCCESS:
        // Nothing to do
        break;

    default:
        log(DEBUG, "State for sniffer parser unknown");
        abort();
        break;
    }
    return p->state;
}