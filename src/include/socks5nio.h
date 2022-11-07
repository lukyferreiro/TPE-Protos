#ifndef __socks5nio_h_
#define __socks5nio_h_

#include "selector.h"
#include <netdb.h>

/** Intenta aceptar la nueva conexión entrante*/
void socksv5_passive_accept(struct selector_key* key);
void socksv5_pool_destroy(void);

#endif