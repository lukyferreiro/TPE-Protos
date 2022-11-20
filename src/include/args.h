#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>
#include <stdint.h>

#define MAX_USERS 10
#define USER_PASSWORD_DELIMETER ':'
#define IDENTIFIER_OF_IPV6 ':'

#define DEFAULT_IPV4_ADDR_PROXY "0.0.0.0"
#define DEFAULT_IPV6_ADDR_PROXY "0::0"
#define DEFAULT_PORT_SOCKS5 1080
#define DEFAULT_IPV4_ADDR_MNG "127.0.0.1"
#define DEFAULT_IPV6_ADDR_MNG "::1"
#define DEFAULT_PORT_MNG 8080
#define DEFAULT_VERSION "1.0"
#define MAX_LEN_USERS 128

#define ALPHA_TKN "ALPHA_TKN"
#define MIN_TOKEN_SIZE 3
#define MAX_TOKEN_SIZE 7

struct users {
    char name[MAX_LEN_USERS];
    char pass[MAX_LEN_USERS];
};

struct socks5_args {
    char* socks_addr;
    char* socks_addr6;
    unsigned short socks_port;

    char* mng_addr;
    char* mng_addr6;
    unsigned short mng_port;

    uint32_t mng_token;

    char* version;

    int nusers;
    struct users users[MAX_USERS];

    bool sniffing;
    bool auth;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando args con 
 * defaults o la seleccion humana. Puede cortar la ejecución.
 */
void parse_args(const int argc, char** argv, struct socks5_args* args);

#endif