#include "user_utils.h"
#include "args.h"
#include <string.h>

extern struct socks5_args socks5_args;

bool user_is_registered(char *user) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (socks5_args.users[i].name[0] != 0 &&
            strcmp(user, socks5_args.users[i].name) == 0)
            return true;
    }
    return false;
}

bool check_credentials(char *user, char *pass) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (socks5_args.users[i].name[0] != 0 &&
            strcmp(user, socks5_args.users[i].name) == 0 &&
            strcmp(pass, socks5_args.users[i].pass) == 0)
            return true;
    }
    return false;
}

bool server_is_full() { return socks5_args.nusers == MAX_USERS; }

void add_user(char *user, char *pass) {
    bool done = false;
    for (int i = 0; i < MAX_USERS && done == false; i++) {
        if (socks5_args.users[i].name[0] == 0) {
            char *usern = socks5_args.users[i].name;
            strcpy(usern, user);
            char *passw = socks5_args.users[i].pass;
            strcpy(passw, pass);
            socks5_args.nusers++;
            done = true;
        }
    }
}

void delete_user(char *user) {
    bool not_found = true;
    for (int i = 0; i < MAX_USERS && not_found; i++) {
        if (socks5_args.users[i].name[0] != 0 &&
            strcmp(user, socks5_args.users[i].name) == 0) {
            socks5_args.nusers--;
            socks5_args.users[i].pass[0] = 0;
            socks5_args.users[i].name[0] = 0;
            not_found = false;
        }
    }
}
