// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <errno.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset */

#include "args.h"

struct socks5_args socks5_args;

static unsigned short port(const char* s) {
    char* end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "Port should be in the range of 1-65536: %s\n", s);
        exit(1);
        return 1;
    }
    return (unsigned short)sl;
}

static void user(char* s, struct users* user) {

    char* p = strchr(s, USER_PASSWORD_DELIMETER);
    if (p == NULL) {
        fprintf(stderr, "Password not found\n");
        exit(1);
    } else {
        *p = 0;
        p++;

        if (strlen(s) > MAX_LEN_USERS) {
            fprintf(stderr, "Username specified is greater than %d\n", MAX_LEN_USERS-1);
            exit(1);
        } else if (strlen(p) > MAX_LEN_USERS) {
            fprintf(stderr, "Password specified is greater than %d\n", MAX_LEN_USERS-1);
            exit(1);
        }

        // TODO: chequear que el usuario no este repetido

        strcpy(user->name, s);
        strcpy(user->pass, p);
    }
}

static void version(void) {
    fprintf(stderr, "SOCKSv5 version: " DEFAULT_VERSION "\n"
                    "ITBA Protocolos de Comunicación 2022/2 -- Grupo 1\n"
                    "ALFA PROTOCOL :) \n"); // TODO
}

static void usage(const char* progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -l <SOCKS addr>  Dirección IPv4 o IPv6 donde servirá el proxy SOCKS.\n"
            "   -L <conf addr>   Dirección IPv6 o IPV6 donde servirá el servicio de management.\n"
            "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
            "   -P <conf port>   Puerto entrante conexiones configuracion\n"
            "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
            "   -v               Imprime información sobre la versión versión y termina.\n"
            "   -N               Deshabilita los passwords disectors.\n"
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
    args->mng_addr = DEFAULT_IPV6_ADDR_MNG;
    args->mng_port = DEFAULT_PORT_MNG;

    args->version = DEFAULT_VERSION;
    args->nusers = 0;

    args->disectors_enabled = true;

    args->authentication = false;

    int c;
    while (true) {
        c = getopt(argc, argv, "hl:L:Np:P:u:v");
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'l':
                // Si encontramos ':', voy a usar IPv6
                if (strchr(optarg, ':') != NULL)
                    args->socks_addr6 = optarg;
                else
                    args->socks_addr = optarg;
                break;
            case 'L':
                // Si encontramos ':', voy a usar IPv6
                if (strchr(optarg, ':') != NULL)
                    args->mng_addr6 = optarg;
                else
                    args->mng_addr = optarg;
                break;
            case 'N':
                args->disectors_enabled = false;
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
                    args->authentication = true;
                }
                break;
            case 'v':
                version();
                exit(0);
                break;
            default:
                fprintf(stderr, "Unknown argument %d.\n", c);
                exit(1);
        }
    }
    if (optind < argc) {
        fprintf(stderr, "Argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
