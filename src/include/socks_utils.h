#ifndef __socks_utils_h_
#define __socks_utils_h_

#include "args.h"
#include "netutils.h"
#include <stdbool.h>

#define MAX_PENDING_CONNECTIONS 20

int create_socket(struct socks5_args* args, addr_type addr_type);
bool valid_user_and_password(char* user, char* pass);
bool valid_user_is_registered(char* user);
bool server_check_if_full();
void delete_user(char *user);
void add_user(char *user, char *pass);

#endif