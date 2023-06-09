// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "args.h"
#include "socks_utils.h"
#include <errno.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <logger.h>
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset */

struct socks5_args socks5_args;

static unsigned short port(const char* s) {
    char* end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "Port should be in the range of 1-65536: %s\n", s);
        exit(EXIT_FAILURE);
        return 1;
    }
    return (unsigned short)sl;
}

static void user(char* s, struct users* user) {
    char* p = strchr(s, USER_PASSWORD_DELIMETER);
    if (p == NULL) {
        fprintf(stderr, "Password not found\n");
        exit(EXIT_FAILURE);
    } else {
        *p = 0;
        p++;

        if (strlen(s) > MAX_LEN_USERS) {
            fprintf(stderr, "Username specified is greater than %d\n", MAX_LEN_USERS);
            exit(EXIT_FAILURE);
        } else if (strlen(p) > MAX_LEN_USERS) {
            fprintf(stderr, "Password specified is greater than %d\n", MAX_LEN_USERS);
            exit(EXIT_FAILURE);
        }

        if (valid_user_is_registered(s)) {
            fprintf(stderr, "User already exists\n");
            exit(EXIT_FAILURE);
        }

        //strcpy(user->name, s);
        //strcpy(user->pass, p);
        memcpy(user->name, s, strlen(s)+1);
        memcpy(user->pass, p, strlen(p)+1);
    }
}

static void version(void) {
    fprintf(stderr, "SOCKSv5 version: " DEFAULT_VERSION "\n"
                    "ITBA Protocolos de Comunicación 2022/2 -- Grupo 1\n"
                    "ALPHA PROTOCOL\n");
}

static void usage(const char* progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -l <SOCKSaddr>   Dirección IPv4 o IPv6 donde servirá el proxy SOCKS.\n"
            "   -L <mng-addr>    Dirección IPv6 o IPV6 donde servirá el servicio de administrador.\n"
            "   -p <SOCKS-port>  Puerto entrante conexiones SOCKS.\n"
            "   -P <mgn-port>    Puerto entrante conexiones configuracion\n"
            "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
            "   -v               Imprime información sobre la versión y termina.\n"
            "   -N               Deshabilita el sniffing.\n"
            "\n",
            progname);
    exit(1);
}

void parse_args(const int argc, char** argv, struct socks5_args* args) {
    memset(args, 0, sizeof(*args)); // Para setear en null los punteros de users

    args->socks_addr = DEFAULT_IPV4_ADDR_PROXY;
    args->socks_addr6 = DEFAULT_IPV6_ADDR_PROXY;
    args->socks_port = DEFAULT_PORT_SOCKS5;

    args->mng_addr = DEFAULT_IPV4_ADDR_MNG;
    args->mng_addr6 = DEFAULT_IPV6_ADDR_MNG;
    args->mng_port = DEFAULT_PORT_MNG;

    char* token = getenv(ALPHA_TKN);
    if (token == NULL) {
        fprintf(stderr, "Check that the environment token %s exists\n", ALPHA_TKN);
        exit(EXIT_FAILURE);
    }
    if (strlen(token) < MIN_TOKEN_SIZE || strlen(token) > MAX_TOKEN_SIZE) {
        fprintf(stderr, "Token must be between %d and %d characters\n", MIN_TOKEN_SIZE, MAX_TOKEN_SIZE);
        exit(EXIT_FAILURE);
    }
    if(!isNumber(token)) {
        fprintf(stderr, "%s must be a numeric token\n", ALPHA_TKN);
        exit(EXIT_FAILURE);
    }
    args->mng_token = (uint32_t) strtoul(token, NULL, 10);

    args->version = DEFAULT_VERSION;
    args->nusers = 0;

    args->sniffing = true;
    args->auth = false;

    while (true) {
        int c = getopt(argc, argv, "hl:L:Np:P:u:v");
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'l':
                // Si encontramos ':', voy a usar IPv6
                if (strchr(optarg, IDENTIFIER_OF_IPV6) != NULL)
                    args->socks_addr6 = optarg;
                else
                    args->socks_addr = optarg;
                break;
            case 'L':
                // Si encontramos ':', voy a usar IPv6
                if (strchr(optarg, IDENTIFIER_OF_IPV6) != NULL)
                    args->mng_addr6 = optarg;
                else
                    args->mng_addr = optarg;
                break;
            case 'N':
                args->sniffing = false;
                break;
            case 'p':
                args->socks_port = port(optarg);
                break;
            case 'P':
                args->mng_port = port(optarg);
                break;
            case 'u':
                if (args->nusers >= MAX_USERS) {
                    fprintf(stderr, "Maximun number of command line users reached: %d.\n", MAX_USERS);
                    exit(1);
                } else {
                    user(optarg, args->users + args->nusers);
                    args->nusers++;
                    args->auth = true;
                }
                break;
            case 'v':
                version();
                exit(EXIT_SUCCESS);
                break;
            default:
                fprintf(stderr, "Unknown argument %d.\n", c);
                exit(EXIT_FAILURE);
        }
    }
    if (optind < argc) {
        fprintf(stderr, "Argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(EXIT_FAILURE);
    }
}
