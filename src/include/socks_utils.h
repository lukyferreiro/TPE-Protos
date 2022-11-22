#ifndef __socks_utils_h_
#define __socks_utils_h_

#include "args.h"
#include "netutils.h"
#include <stdbool.h>

#define MAX_PENDING_CONNECTIONS 20

/**
 * @brief Crea un nuevo socket
 */
int create_socket(struct socks5_args* args, addr_type addr_type, bool is_udp);

/**
 * @brief Valida si el usuario y contraseña son correctos 
 * 
 * @return Retorna si tuvo exito o no
 */
bool valid_user_and_password(char* user, char* pass);

/**
 * @brief Valida si el usuario ya se encuentra registrado
 * 
 * @return Retorna si tuvo exito o no
 */
bool valid_user_is_registered(char* user);

/**
 * @brief Elimina un usuario
 */
void delete_user(char *user);

/**
 * @brief Agrega un usuario
 */
void add_user(char *user, char *pass);

/**
 * @brief Convierte el string recibido a numero
 * 
 * @return Retorna si tuvo exito o no
 */
bool isNumber(char* s);

#endif