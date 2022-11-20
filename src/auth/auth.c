// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "auth.h"
#include "logger.h"

void auth_parser_init(struct auth_parser* p) {
    p->state = AUTH_VERSION;
    p->status = AUTH_VALID;
    p->version = AUTH_VERSION_VALUE;
}

enum auth_state auth_parser_feed(struct auth_parser* p, const uint8_t b) {

    switch (p->state) {
        // Segun el estado en el que me encuentre, paso al siguiente
        case AUTH_VERSION:
            if (b == p->version) {
                p->state = AUTH_USERNAME_LEN;
            } else {
                p->state = AUTH_ERROR;
                p->status = AUTH_INVALID_VERSION;
            }
            break;
        case AUTH_USERNAME_LEN:
            if (b < 1) {
                p->state = AUTH_ERROR;
                p->status = AUTH_INVALID_USERNAME_LEN;
            } else {
                p->state = AUTH_USERNAME;
                p->username.user_len = b;
                p->credentials = 0;
            }
            break;
        case AUTH_USERNAME:
            p->username.user[p->credentials++] = (char)b;
            if (p->credentials == p->username.user_len) {
                p->username.user[p->credentials] = 0;
                p->state = AUTH_PASSWORD_LEN;
            }
            break;
        case AUTH_PASSWORD_LEN:
            if (b < 1) {
                p->state = AUTH_ERROR;
                p->status = AUTH_INVALID_PASSWORD_LEN;
            } else {
                p->state = AUTH_PASSWORD;
                p->password.pass_len = b;
                p->credentials = 0;
            }
            break;
        case AUTH_PASSWORD:
            p->password.pass[p->credentials++] = (char)b;
            if (p->credentials == p->password.pass_len) {
                p->password.pass[p->credentials] = 0;
                p->state = AUTH_DONE;
            }
            break;
        case AUTH_DONE:
        case AUTH_ERROR:
            // Nada para hacer
            break;
        default:
            log(DEBUG, "Unknown state on auth parser");
            abort();
            break;
    }
    return p->state;
}

bool auth_parser_consume(buffer* buffer, struct auth_parser* p, bool* errored) {
    uint8_t byte;
    while (!auth_parser_is_done(p->state, errored) && buffer_can_read(buffer)) {
        byte = buffer_read(buffer);
        p->state = auth_parser_feed(p, byte);
    }
    return auth_parser_is_done(p->state, errored);
}

bool auth_parser_is_done(enum auth_state state, bool* errored) {
    if (errored != NULL) {
        if (state == AUTH_ERROR)
            *errored = true;
        else
            *errored = false;
    }
    if (state == AUTH_ERROR || state == AUTH_DONE)
        return true;
    return false;
}

char* auth_parser_error(struct auth_parser* p) {
    switch (p->status) {
        case AUTH_VALID:
            return "No error";
            break;
        case AUTH_INVALID_VERSION:
            return "Invalid version provided";
            break;
        case AUTH_INVALID_USERNAME_LEN:
            return "Invalid username length";
            break;
        case AUTH_INVALID_PASSWORD_LEN:
            return "Invalid password length";
            break;
        default:
            return "Error";
            break;
    }
}

void auth_parser_close(struct auth_parser* p) {
    // Nada que hacer
}

int auth_parser_marshall(buffer* b, const uint8_t status, uint8_t version) {
    size_t n;
    uint8_t* buff = buffer_write_ptr(b, &n);

    if (n < AUTH_RESPONSE_LEN) {
        return -1;
    }

    buff[0] = version;
    buff[1] = status;
    buffer_write_adv(b, AUTH_RESPONSE_LEN);
    return AUTH_RESPONSE_LEN;
}