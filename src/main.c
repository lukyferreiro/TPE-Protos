// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

/**
 * Interpreta los argumentos de línea de comandos, y monta un socket pasivo.
 * Todas las conexiones entrantes se manejarán en éste hilo.
 * Se descargará en otro hilos las operaciones bloqueantes
 */
#include "args.h"
#include "buffer.h"
#include "alpha_manager.h"
#include "logger.h"
#include "netutils.h"
#include "selector.h"
#include "socks5nio.h"
#include "socks_utils.h"
#include "statistics_utils.h"
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h> // socket
#include <sys/types.h>  // socket
#include <unistd.h>

#define DEFAULT_FDS_SIZE 2
#define SELECTOR_SIZE 1024

static bool done = false;
extern struct socks5_args socks5_args;
extern struct socks5_stats socks5_stats;

static void sigterm_handler(const int signal) {
    printf("Signal %d, cleaning up and exiting\n", signal);
    done = true;
}

int main(const int argc, char** argv) {
    // No tenemos nada que leer de stdin
    close(STDIN_FILENO);

    const char* err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;
    int ret = 0;
    int fd = -1;
    int fds_socks5[DEFAULT_FDS_SIZE];
    int fds_socks5_size = 0;
    int fds_mng[DEFAULT_FDS_SIZE];
    int fds_mng_size = 0;

    parse_args(argc, argv, &socks5_args);
    init_stats(&socks5_stats);

    //---------------------------------------------------------------
    // Creamos los sockets pasivos IPv4 e IPv6 para el proxy SOCKSv5
    //---------------------------------------------------------------
    fd = create_socket(&socks5_args, ADDR_IPV4, false);
    if (fd < 0) {
        log(DEBUG, "Cannot create IPv4 passive socket of SOCKSv5");
    } else if (selector_fd_set_nio(fd) == -1) {
        perror("selector_fd_set_nio");
        err_msg = "Error getting SOCKSv5 server IPv4 socket as non blocking";
        goto finally;
    } else {
        fds_socks5[fds_socks5_size++] = fd;
    }

    fd = create_socket(&socks5_args, ADDR_IPV6, false);
    if (fd < 0) {
        log(DEBUG, "Cannot create IPv6 passive socket of SOCKSv5");
    } else if (selector_fd_set_nio(fd) == -1) {
        perror("selector_fd_set_nio");
        err_msg = "Error getting SOCKSv5 server IPv6 socket as non blocking";
        goto finally;
    } else {
        fds_socks5[fds_socks5_size++] = fd;
    }

    if (fds_socks5_size == 0) {
        log(FATAL, "Cannot create any socket for SOCKSv5 server");
    }

    //---------------------------------------------------------------
    // Creamos los sockets pasivos IPv4 e IPv6 para el administador
    //---------------------------------------------------------------
    fd = create_socket(&socks5_args, ADDR_IPV4, true);
    if (fd < 0) {
        log(DEBUG, "Cannot create IPv4 passive socket for manager");
    } else if (selector_fd_set_nio(fd) == -1) {
        perror("selector_fd_set_nio");
        err_msg = "Error getting manager server IPv4 socket as non blocking";
        goto finally;
    } else {
        fds_mng[fds_mng_size++] = fd;
    }

    fd = create_socket(&socks5_args, ADDR_IPV6, true);
    if (fd < 0) {
        log(DEBUG, "Cannot create IPv6 passive socket for manager");
    } else if (selector_fd_set_nio(fd) == -1) {
        perror("selector_fd_set_nio");
        err_msg = "Error getting manager IPv6 socket as non blocking";
        goto finally;
    } else {
        fds_mng[fds_mng_size++] = fd;
    }

    if (fds_mng_size == 0) {
        log(FATAL, "Cannot create any socket for manager");
    }

    //---------------------------------------------------------------

    // Registrar sigterm es útil para terminar el programa normalmente.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        },
    };

    if (selector_init(&conf) != 0) {
        err_msg = "Cannot initialize selector";
        goto finally;
    }

    selector = selector_new(SELECTOR_SIZE);
    if (selector == NULL) {
        err_msg = "Cannot create selector";
        goto finally;
    }

    //----------------------------------------------
    // Registramos los sockets del servidor SOCKSv5
    //----------------------------------------------
    const struct fd_handler socksv5 = {
        .handle_read = socksv5_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL, // Nada que liberar
    };

    for (int i = 0; i < fds_socks5_size; i++) {
        ss = selector_register(selector, fds_socks5[i], &socksv5, OP_READ, NULL);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "Error registering in selector an fd of SOCKSv5";
            goto finally;
        }
    }

    //----------------------------------------------
    // Registramos los sockets del administrador
    //----------------------------------------------
    const struct fd_handler manager = {
        .handle_read = manager_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL, // nada que liberar
    };

    for (int i = 0; i < fds_mng_size; i++) {
        ss = selector_register(selector, fds_mng[i], &manager, OP_READ, NULL);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "Error registering server manager fd";
            goto finally;
        }
    }

    for (; !done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            log(LOG_ERROR, "%s", selector_error(ss));
            err_msg = "Error serving";
            goto finally;
        }
    }
    if (err_msg == NULL) {
        err_msg = "Everything it's fine. Closing";
    }

finally:
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", err_msg, ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
        ret = 2;
    } else if (err_msg) {
        perror(err_msg);
        ret = 1;
    }

    if (selector != NULL) {
        selector_destroy(selector);
    }

    selector_close();

    for (int i = 0; i < fds_socks5_size; i++) {
        close(fds_socks5[i]);
    }
    for (int i = 0; i < fds_mng_size; i++) {
        close(fds_mng[i]);
    }

    socksv5_pool_destroy();

    return ret;
}