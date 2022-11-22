#ifndef __ALPHA_MANAGER_H_
#define __ALPHA_MANAGER_H_

#include "selector.h"

/**
 * @brief Handler que atiende las conexiones del manager
 * 
 * @param key Estructura con la informacion del fd solicitado
 */
void manager_passive_accept(struct selector_key* key);

#endif