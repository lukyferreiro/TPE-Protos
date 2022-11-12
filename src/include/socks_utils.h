#ifndef __socks_utils_h_
#define __socks_utils_h_

#include "args.h"
#include "netutils.h"
#include <stdbool.h>

#define MAX_PENDING_CONNECTIONS 20

int create_socket(struct socks5_args* args, addr_type addr_type);

#endif