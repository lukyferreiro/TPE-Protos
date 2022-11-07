// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

/**
 * Parser del hello de SOCKS5
 */
#include <stdio.h>
#include <stdlib.h>

#include "hello.h"

extern void hello_parser_init(struct hello_parser* p, void (*on_authentication_method)(hello_parser* p, uint8_t method)) {
    p->state = HELLO_VERSION;
    p->on_authentication_method = on_authentication_method;
    p->remaining = 0;
}

extern enum hello_state hello_parser_feed(struct hello_parser* p, const uint8_t b) {
    switch (p->state) {
        case HELLO_VERSION:
            if (0x05 == b) { // Version 5 de socks
                p->state = HELLO_NMETHODS;
            } else {
                p->state = HELLO_ERROR_UNSUPPORTED_VERSION;
            }
            break;

        case HELLO_NMETHODS:
            p->remaining = b;
            p->state = b > 0 ? HELLO_METHODS : HELLO_DONE;
            break;

        case HELLO_METHODS:
            if (p->on_authentication_method != NULL) {
                p->on_authentication_method(p, b);
            }
            p->remaining--;
            if (p->remaining <= 0) {
                p->state = HELLO_DONE;
            }
            break;
        case HELLO_DONE:
        case HELLO_ERROR_UNSUPPORTED_VERSION:
            // nada que hacer, nos quedamos en este estado
            break;
        default:
            fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }

    return p->state;
}

extern enum hello_state hello_parser_consume(buffer* b, struct hello_parser* p, bool* errored) {
    /* enum hello_state st = p->state;
    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = hello_parser_feed(p, c);
        if (hello_is_done(st, errored)) {
            break;
        }
    }
    return st; */

    uint8_t byte;
    while (!hello_parser_is_done(p->state, errored) && buffer_can_read(b)) {
        byte = buffer_read(b);
        p->state = hello_parser_feed(p, byte);
    }
    return hello_parser_is_done(p->state, errored);
}

extern bool hello_parser_is_done(const enum hello_state state, bool* errored) {
    /* bool ret;
    switch (state) {
        case HELLO_ERROR_UNSUPPORTED_VERSION:
            if (0 != errored) {
                *errored = true;
            }
            // no break
        case HELLO_DONE:
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
    return ret; */

    if (errored != NULL) {
        if (state == HELLO_ERROR_UNSUPPORTED_VERSION) {
            *errored = true;
        } else {
            *errored = false;
        }
    }
    if (state == HELLO_ERROR_UNSUPPORTED_VERSION || state == HELLO_DONE)
        return true;
    return false;
}

extern const char* hello_parser_error(const struct hello_parser* p) {
    char* ret;
    switch (p->state) {
        case HELLO_DONE:
        case HELLO_VERSION:
        case HELLO_NMETHODS:
        case HELLO_METHODS:
            ret = "No error";
            break;
        case HELLO_ERROR_UNSUPPORTED_VERSION:
        default:
            ret = "Unsupported version";
            break;
    }
    return ret;
}

extern void hello_parser_close(struct hello_parser* p) {
    /* No hay nada que liberar */
}

extern int hello_parser_marshall(buffer* b, const uint8_t method) {
    size_t n;
    uint8_t* buff = buffer_write_ptr(b, &n);
    if (n < 2) {
        return -1;
    }
    buff[0] = 0x05; // Version de socks 5
    buff[1] = method;
    buffer_write_adv(b, 2);
    return 2;
}
