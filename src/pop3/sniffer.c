#include "sniffer.h"
#include <ctype.h>
#include <string.h>

// https://www.rfc-es.org/rfc/rfc1939-es.txt

// Respuestas establecidas por el RFC
static const char* OK = "+OK";
static const char* USER = "USER ";
static const char* PASS = "PASS ";
static const char* ERR = "-ERR";

static enum sniffer_state user_message(struct sniffer_parser* p, uint8_t b);
static enum sniffer_state pass_message(struct sniffer_parser* p, uint8_t b);
static enum sniffer_state read_username(struct sniffer_parser* p, uint8_t b);
static enum sniffer_state read_password(struct sniffer_parser* p, uint8_t b);
static enum sniffer_state ok_message(struct sniffer_parser* p, uint8_t b);
static enum sniffer_state check_ok(struct sniffer_parser* p, uint8_t b);

static enum sniffer_state user_message(struct sniffer_parser* p, uint8_t b) {
    if (tolower(b) == tolower(*(USER + p->bytes_read))) {
        p->bytes_read++;
        p->bytes_remaining--;
        if (p->bytes_remaining == 0) {
            p->bytes_read = 0;
            return SNIFFER_READ_USER;
        }
    } else if (p->bytes_read != 0) {
        p->bytes_read = 0;
        p->bytes_remaining = strlen(USER);
    }
    return SNIFFER_USER;
}

static enum sniffer_state pass_message(struct sniffer_parser* p, uint8_t b) {
    if (tolower(b) == tolower(*(PASS + p->bytes_read))) {
        p->bytes_read++;
        p->bytes_remaining--;
        if (p->bytes_remaining == 0) {
            p->bytes_read = 0;
            return SNIFFER_READ_PASS;
        }
    } else if (p->bytes_read != 0) {
        p->bytes_read = 0;
        p->bytes_remaining = strlen(PASS);
    }
    return SNIFFER_PASS;
}

static enum sniffer_state read_username(struct sniffer_parser* p, uint8_t b) {
    if (b != '\n') {
        if (p->bytes_read < MAX_LEN_USERS) {
            p->username[p->bytes_read++] = b;
        }
    } else {
        p->username[p->bytes_read] = '\0';
        p->bytes_read = 0;
        p->bytes_remaining = strlen(PASS);
        return SNIFFER_PASS;
    }
    return SNIFFER_READ_USER;
}

static enum sniffer_state read_password(struct sniffer_parser* p, uint8_t b) {
    if (b != '\n') {
        if (p->bytes_read < MAX_LEN_USERS) {
            p->password[p->bytes_read++] = b;
        }
    } else {
        p->password[p->bytes_read] = '\0';
        p->bytes_read = 0;
        return SNIFFER_CHECK_OK;
    }
    return SNIFFER_READ_PASS;
}

static enum sniffer_state ok_message(struct sniffer_parser* p, uint8_t b) {
    if (tolower(b) == tolower(*(OK + p->bytes_read))) {
        p->bytes_read++;
        p->bytes_remaining--;
        if (p->bytes_remaining == 0) {
            p->bytes_read = 0;
            p->bytes_remaining = strlen("USER ");
            return SNIFFER_USER;
        }
    } else {
        return SNIFFER_ERROR;
    }
    return SNIFFER_OK;
}

static enum sniffer_state check_ok(struct sniffer_parser* p, uint8_t b) {
    if (tolower(b) == tolower(*(OK + p->bytes_read))) {
        p->bytes_read++;
        if (p->bytes_read == strlen(OK)) {
            return SNIFFER_SUCCESS;
        }
    } else if (tolower(b) == tolower(*(ERR + p->bytes_read))) {
        p->bytes_read++;
        if (p->bytes_read == strlen(ERR)) {
            return SNIFFER_USER;
        }
    }
    return SNIFFER_CHECK_OK;
}

void sniffer_parser_init(sniffer_parser* p) {
    buffer_init(&p->buffer, N(p->raw_buff), p->raw_buff);
    p->state = SNIFFER_OK;
    p->bytes_read = 0;
    p->bytes_remaining = strlen(OK);
    p->is_initiated = true;
}

enum sniffer_state sniffer_parser_feed(sniffer_parser* p, const uint8_t b) {
    switch (p->state) {
        case SNIFFER_OK:
            p->state = ok_message(p, b);
            break;
        case SNIFFER_USER:
            p->state = user_message(p, b);
            break;
        case SNIFFER_READ_USER:
            p->state = read_username(p, b);
            break;
        case SNIFFER_PASS:
            p->state = pass_message(p, b);
            break;
        case SNIFFER_READ_PASS:
            p->state = read_password(p, b);
            break;
        case SNIFFER_CHECK_OK:
            p->state = check_ok(p, b);
            break;
        case SNIFFER_ERROR:
        case SNIFFER_SUCCESS:
            // Nada para hacer
            break;
        default:
            log(DEBUG, "Unknown state of sniffer parser");
            abort();
            break;
    }
    return p->state;
}

enum sniffer_state sniffer_parser_consume(struct sniffer_parser* p) {
    uint8_t byte;
    while (!sniffer_parser_is_done(p) && buffer_can_read(&p->buffer)) {
        byte = buffer_read(&p->buffer);
        p->state = sniffer_parser_feed(p, byte);
    }

    return sniffer_parser_is_done(p);
}

bool sniffer_parser_is_done(struct sniffer_parser* p) {
    if (p->state == SNIFFER_SUCCESS) {
        log(INFO, "%s\n", p->username);
        log(INFO, "%s\n", p->password);
        return true;
    }
    return false;
}

char* sniffer_parser_error(struct sniffer_parser* p) {
    char* ret;
    switch (p->state) {
        case SNIFFER_OK:
        case SNIFFER_USER:
        case SNIFFER_READ_USER:
        case SNIFFER_PASS:
        case SNIFFER_READ_PASS:
        case SNIFFER_CHECK_OK:
        case SNIFFER_SUCCESS:
            ret = "No error";
            break;
        case SNIFFER_ERROR:
        default:
            ret = "Error";
            break;
    }
    return ret;
}

void sniffer_parser_close(struct sniffer_parser* p) {
    // Nada para hacer
}