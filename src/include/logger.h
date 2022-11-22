#ifndef __LOGGER_H_
#define __LOGGER_H_

#include <errno.h>
#include <limits.h> /* LONG_MIN et al */
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>      /* for printf */
#include <stdlib.h>     /* for exit */
#include <string.h>     /* memset */
#include <sys/socket.h> // socket
#include <sys/types.h>  // socket
#include <unistd.h>

//TODO comentar este define para que no aparezcan los logs de debug
//#define IS_DEBUG 1

typedef enum { DEBUG = 0, INFO, LOG_ERROR, FATAL } LOG_LEVEL;

extern LOG_LEVEL current_level;

/**
 * @brief Deja en el buffer recibido como parametro la fecha actual
 */
void get_date_buff(char* buff);

/**
 * @brief Setea el log level
 */
void setLogLevel(LOG_LEVEL newLevel);

/**
 * @brief Retorna el log level como string
 */
char* levelDescription(LOG_LEVEL level);

/**
 * @brief Loguea segun el log level y el formato y argumetos recibidos
 */
void logger(LOG_LEVEL level, const char* fmt, ...);

/**
 * @brief Funcion que loguea unicamente en DEBUG
 * Esta funciona si el define IS_DEBUG esta encendido
 */
void log_debug(const char* fmt, ...);

/**
 * @brief Imprime el usuario y la contraseña sniffeadas mediante POP3
 */
void sniffer_logger(char* username, char* password);

// Debe ser una macro para poder obtener nombre y linea de archivo.
/* #define log(level, fmt, ...)                                                             \
    {                                                                                    \
        if (level >= current_level) {                                                    \
            fprintf(stderr, "%s: %s:%d, ", levelDescription(level), __FILE__, __LINE__); \
            fprintf(stderr, fmt, ##__VA_ARGS__);                                         \
            fprintf(stderr, "\n");                                                       \
        }                                                                                \
        if (level == FATAL)                                                              \
            exit(1);                                                                     \
    }
*/

#endif  