#ifndef __socks5nio_h_
#define __socks5nio_h_

#include "selector.h"
#include <netdb.h>

/**
 * @brief Handler del socket pasivo que atiende conexiones socksv5
 * Intenta aceptar la nueva conexión entrante
 */
void socksv5_passive_accept(struct selector_key* key);

/**
 * @brief Libera pools internos
 * 
 */
void socksv5_pool_destroy(void);

#endif