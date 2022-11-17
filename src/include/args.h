#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>

#define MAX_USERS 10
#define MAX_CRED_SIZE 255
#define USER_PASSWORD_DELIMETER ':'

#define DEFAULT_IPV4_ADDR_PROXY "0.0.0.0"
#define DEFAULT_IPV6_ADDR_PROXY "0::0"
#define DEFAULT_PORT_SOCKS5 1080
#define DEFAULT_IPV4_ADDR_MNG "127.0.0.1"
#define DEFAULT_IPV6_ADDR_MNG "::1"
#define DEFAULT_PORT_MNG 8080
#define DEFAULT_VERSION "1.0"

struct users {
    char* name;
    char* pass;
};

struct socks5_args {
    char* socks_addr;
    char* socks_addr6;
    unsigned short socks_port;

    char* mng_addr;
    char* mng_addr6;
    unsigned short mng_port;

    char* version;

    int nusers;
    struct users users[MAX_USERS];

    uint32_t        manager_token;
    bool            sniffing;
    bool            auth;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void parse_args(const int argc, char** argv, struct socks5_args* args);

#endif