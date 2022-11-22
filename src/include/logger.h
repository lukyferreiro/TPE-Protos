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

/*
** Minimo nivel de log a registrar.
** Cualquier llamada a log con un nivel mayor a newLevel sera ignorada
*/
char* get_date(void);
void get_date_buff(char* buff);
void setLogLevel(LOG_LEVEL newLevel);
char* levelDescription(LOG_LEVEL level);
void logger(LOG_LEVEL level, const char* fmt, ...);
void log_debug(const char* fmt, ...);
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
