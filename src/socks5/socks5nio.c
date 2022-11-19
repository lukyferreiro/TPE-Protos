// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

/**
 * Controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include <arpa/inet.h>
#include <assert.h> // assert
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h> // malloc
#include <string.h> // memset
#include <time.h>
#include <unistd.h> // close

#include "args.h"
#include "auth.h"
#include "buffer.h"
#include "hello.h"
#include "logger.h"
#include "netutils.h"
#include "request.h"
#include "socks5nio.h"
#include "stm.h"

#define N(x) (sizeof(x) / sizeof((x)[0]))
/** Obtiene el struct (socks5 *) desde la llave de selección */
#define ATTACHMENT(key) ((struct socks5*)(key)->data)

static const unsigned max_pool = 50; // Tamaño maximo
static unsigned pool_size = 0;       // Tamaño actual
static struct socks5* pool = 0;      // Pool propiamente dicho

struct socks5_args socks5_args;

/** Maquina de estados general */
enum socks_v5state {
    /**
     * Recibe el mensaje 'hello' del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no esté completo
     *   - HELLO_WRITE cuando está completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    HELLO_READ,

    /**
     * Envía la respuesta del 'hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    HELLO_WRITE,

    /**
     * Recibe el mensaje 'request' del cliente e inicia su proceso
     *
     * * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_READ         mientras el mensaje no este completo
     *   - REQUEST_RESOLV       si requiere resolver un nombre DNS
     *   - REQUEST_CONNECTING   si no require resolver un DNS, y podemos iniciar la conexcion al origin server
     *   - REQUEST_WRITE        si determinamos que el mensaje no lo podemos procesar
     *   - ERROR                ante cualquier error (IO/parseo)
     */
    REQUEST_READ,

    /**
     * Envía la respuesta del 'request' al cliente
     *
     * * Intereses:
     *     - OP_WRITE sobre cliet_fd
     *     - OP_NOOP sobre origin_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras quedan bytes por enviar
     *   - COPY         si el request fue exitoso y tenemos que copiar el contenido de los fds
     *   - ERROR        ante I/O error
     */
    REQUEST_WRITE,

    /**
     * Espera la resolucion DNS (llamar a getaddrinfo)
     *
     * * Intereses:
     *     - OP_NOOP sobre client_fd (espera un evento de que la tarea bloquenate termino)
     *
     * Transiciones:
     *   - REQUEST_CONNECTING   si se lorga resolver el nombre y se puede inicar la conexion al origin server
     *   - REQUEST_WRITE        en otro caso
     */
    REQUEST_RESOLV,

    /**
     * Crea el socket activo. Setear no bloqueante
     * Espera que se establezca la conexion al origin server
     *
     * * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_WRITE        se haya logrado o no establecer conexion
     */
    REQUEST_CONNECTING,

    /**
     * Copia los bytes entre el fd_cliente y el fd_destino
     *
     * * Intereses (tanto para client_fd y origin_fd):
     *     - OP_READ si hay espacio para escribir en el buffer de lectura
     *     - OP_WRITE si hay bytes para leer en el buffer de escritura
     *
     * Transiciones:
     *   - DONE     cuando no queda nada mas por copiar
     */
    COPY,

    USERPASS_READ,
    USERPASS_WRITE,

    // Estados terminales
    DONE,
    ERROR,
};

/** Usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    buffer* rb; // Buffer de escritura utilizado para I/O
    buffer* wb; // Buffer de lectura utilizado para I/O
    struct hello_parser parser;
    uint8_t method; // El metodo de autenticacion seleccionado
};

/** Usado por REQUEST_READ, REQUEST_WRITE, REQUEST_RESOLV */
struct request_st {
    buffer* rb; // Buffer de escritura utilizado para I/O
    buffer* wb; // Buffer de lectura utilizado para I/O

    struct request request;
    struct request_parser parser;

    enum socks5_response_status status; // Resumen de la respuesta a enviar

    /** A donde nos tenemos que conectar ? */
    struct sockaddr_storage* origin_addr;
    socklen_t* origin_addr_len;
    int* origin_domain;

    const int* client_fd;
    int* origin_fd;
};

/** Usado por REQUEST_CONNECTING*/
struct connecting {
    buffer* wb;
    const int* client_fd;
    int* origin_fd;
    enum socks5_response_status* status;
};

struct copy {
    buffer* rb;
    buffer* wb;
    int* fd;
    fd_interest duplex;
    struct copy* other;
};

struct auth_st {
    buffer* rb;
    buffer* wb;
    struct auth_parser parser;
    uint8_t status;

    uint8_t user_len;
    char username[MAX_LEN_USERS];
    uint8_t pass_len;
    char password[MAX_LEN_USERS];
};

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {

    /** Informacion del cliente */
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;

    /** Resolucion de la direccion del origin server */
    struct addrinfo* origin_resolution;
    /** Intento actual de la direccion del origin server */
    struct addrinfo* origin_resolution_current;

    /** Informacion del origin server */
    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;
    int origin_domain;
    int origin_fd;

    struct state_machine stm; // Maquinas de estados

    /** Estados para el client_fd */
    union {
        struct hello_st hello;
        struct request_st request;
        struct copy copy;
        struct auth_st auth;
    } client;

    /** Estados para el origin_fd */
    union {
        struct connecting conn;
        struct copy copy;
    } orig;

    /** Buffers para ser usados read_buffers y write_buffer */
    uint8_t raw_buff_a[BUFFER_SIZE];
    uint8_t raw_buff_b[BUFFER_SIZE];
    buffer read_buffer;
    buffer write_buffer;

    /** Cantidad de referencias a este objeto. Si es uno se debe destruir */
    unsigned references;

    /** Siguiente en el pool */
    struct socks5* next;
};

//-----------------------------------------------------------------------------
static struct socks5* socks5_new(int client_fd);

static void socks5_destroy_(struct socks5* s);
static void socks5_destroy(struct socks5* s);

/**
 * Declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 * Handlers top level de la conexión pasiva.
 * son los que emiten los eventos a la maquina de estados.
 */
static void socksv5_read(struct selector_key* key);
static void socksv5_write(struct selector_key* key);
static void socksv5_block(struct selector_key* key);
static void socksv5_close(struct selector_key* key);
static void socksv5_done(struct selector_key* key);

// Declaraciones de hello
static void on_hello_method(struct hello_parser* p, const uint8_t method);
static void hello_read_init(const unsigned state, struct selector_key* key);
static unsigned hello_process(const struct hello_st* d);
static unsigned hello_read(struct selector_key* key);
static unsigned hello_write(struct selector_key* key);
static void hello_read_close(const unsigned state, struct selector_key* key);

// Declaraciones de request
static void request_init(const unsigned state, struct selector_key* key);
static unsigned request_process(struct selector_key* key, struct request_st* d);
static void* request_resolv_blocking(void* data);
static unsigned request_connect_to_origin(struct selector_key* key, struct request_st* d);
static unsigned request_read(struct selector_key* key);
static unsigned request_resolv_done(struct selector_key* key);
static void request_connecting_init(const unsigned state, struct selector_key* key);
static unsigned request_connecting(struct selector_key* key);
static unsigned request_write(struct selector_key* key);
static void request_read_close(const unsigned state, struct selector_key* key);

// Declaraciones de copy
static void copy_init(const unsigned state, struct selector_key* key);
static fd_interest copy_compute_interests(fd_selector s, struct copy* d);
static struct copy* copy_prt(struct selector_key* key);
static unsigned copy_read(struct selector_key* key);
static unsigned copy_write(struct selector_key* key);

// Declaraciones de userpass
static void auth_init(const unsigned state, struct selector_key* key);
static unsigned auth_process(struct auth_st* d);
static unsigned auth_read(struct selector_key* key);
static unsigned auth_write(struct selector_key* key);
//-----------------------------------------------------------------------------

static const struct fd_handler socks5_handler = {
    .handle_read = socksv5_read,
    .handle_write = socksv5_write,
    .handle_close = socksv5_close,
    .handle_block = socksv5_block,
};

/** Definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state = HELLO_READ,
        .on_arrival = hello_read_init,
        .on_departure = hello_read_close,
        .on_read_ready = hello_read,
    },
    {
        .state = HELLO_WRITE,
        .on_write_ready = hello_write,
    },
    {
        .state = REQUEST_READ,
        .on_arrival = request_init,
        .on_departure = request_read_close,
        .on_read_ready = request_read,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state = REQUEST_RESOLV,
        .on_block_ready = request_resolv_done,
    },
    {
        .state = REQUEST_CONNECTING,
        .on_arrival = request_connecting_init,
        .on_write_ready = request_connecting,
    },
    {
        .state = COPY,
        .on_arrival = copy_init,
        .on_read_ready = copy_read,
        .on_write_ready = copy_write,
    },
    {
        .state = USERPASS_READ,
        .on_arrival = auth_init,
        .on_read_ready = auth_read,
    },
    {
        .state = USERPASS_WRITE,
        .on_write_ready = auth_write,
    },
    {.state = DONE},
    {.state = ERROR}};

////////////////////////////////////////////////////////////////////////////////
//-----------------------------------SOCKS5-------------------------------------
////////////////////////////////////////////////////////////////////////////////

/** Crea un nuevo 'struct socks5' */
static struct socks5* socks5_new(int client_fd) {
    struct socks5* ret;

    if (pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret = pool;
        pool = pool->next;
        ret->next = 0;
    }
    if (ret == NULL) {
        log(LOG_ERROR, "Failed to create socks");
        goto finally;
    }

    memset(ret, 0x00, sizeof(*ret));

    ret->origin_fd = -1;
    ret->client_fd = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);
    ret->stm.initial = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states = client_statbl;

    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    ret->references = 1;

finally:
    return ret;
}

/** Realmente destruye */
static void socks5_destroy_(struct socks5* s) {
    if (s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * Destruye un  `struct socks5', tiene en cuenta las referencias y el pool de objetos.
 */
static void socks5_destroy(struct socks5* s) {
    if (s == NULL) {
        // Nada para hacer
    } else if (s->references == 1) {
        if (s != NULL) {
            if (pool_size < max_pool) {
                s->next = pool;
                pool = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for (s = pool; s != NULL; s = next) {
        next = s->next;
        log(DEBUG, "Socks5 pool destroy");
        if (s->origin_resolution != NULL) {
            free(s->origin_resolution);
        }
        close(s->origin_fd);
        close(s->client_fd);
        free(s);
    }
    pool = NULL;
}

static void socksv5_read(struct selector_key* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);
    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_write(struct selector_key* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);
    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_block(struct selector_key* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);
    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_close(struct selector_key* key) {
    socks5_destroy(ATTACHMENT(key));
}

static void socksv5_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };

    for (unsigned i = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            if (selector_unregister_fd(key->s, fds[i]) != SELECTOR_SUCCESS) {
                abort();
            }
            close(fds[i]);
        }
    }
    log(DEBUG, "Connection closed");
}

void socksv5_passive_accept(struct selector_key* key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct socks5* state = NULL;
    selector_status status = SELECTOR_SUCCESS;

    const int client = accept(key->fd, (struct sockaddr*)&client_addr, &client_addr_len);

    if (client == -1) {
        log(LOG_ERROR, "Fail to accept client connection");
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1) {
        log(LOG_ERROR, "Fail to set non block");
        goto fail;
    }

    state = socks5_new(client);
    if (state == NULL) {
        log(LOG_ERROR, "Fail to create new socks5 connection");
        goto fail;
    }

    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if (selector_register(key->s, client, &socks5_handler, OP_READ, state) != SELECTOR_SUCCESS) {
        log(LOG_ERROR, "Error while registering in selector");
        goto fail;
    }

    log(DEBUG, "New connection created");
    return;

fail:
    if (client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

////////////////////////////////////////////////////////////////////////////////
//------------------------------------HELLO-------------------------------------
////////////////////////////////////////////////////////////////////////////////

/** Callback del parser utilizado en 'read_hello' */
static void on_hello_method(struct hello_parser* p, const uint8_t method) {
    uint8_t* selected = p->data;

    if (socks5_args.authentication == true) {
        if (METHOD_AUTHENTICATION == method) {
            *selected = method;
        }
    } else if (METHOD_NO_AUTHENTICATION_REQUIRED == method) {
        *selected = method;
    }
}

/** Inicializa las variables de los estados HELLO_… */
static void hello_read_init(const unsigned state, struct selector_key* key) {
    struct socks5* s = ATTACHMENT(key);
    struct hello_st* d = &s->client.hello;
    d->rb = &(s->read_buffer);
    d->wb = &(s->write_buffer);
    d->parser.data = &d->method;
    /* d->parser.on_authentication_method = on_hello_method;
    hello_parser_init(&d->parser); */
    *((uint8_t*)d->parser.data) = METHOD_NO_ACCEPTABLE_METHODS;
    hello_parser_init(&d->parser, on_hello_method);
}

/** Lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned hello_read(struct selector_key* key) {
    struct socks5* s = ATTACHMENT(key);
    struct hello_st* d = &s->client.hello;
    unsigned ret = HELLO_READ;
    bool error = false;

    // Leo bytes del socket y los dejo en el buffer
    size_t count;
    uint8_t* ptr = buffer_write_ptr(d->rb, &count);
    ssize_t n = recv(key->fd, ptr, count, 0);

    if (n > 0) {
        buffer_write_adv(d->rb, n);
        if (hello_parser_consume(d->rb, &d->parser, &error)) {
            if (selector_set_interest_key(key, OP_WRITE) == SELECTOR_SUCCESS) {
                ret = hello_process(d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/** Procesamiento del mensaje 'hello' */
static unsigned hello_process(const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;
    uint8_t m = d->method;

    if (hello_parser_marshall(d->wb, m) == -1) {
        ret = ERROR;
    }
    if (METHOD_NO_ACCEPTABLE_METHODS == m) {
        ret = ERROR;
    }

    return ret;
}

/** Escribe todos los bytes de la respuesta al mensaje 'hello' */
static unsigned hello_write(struct selector_key* key) {
    struct socks5* s = ATTACHMENT(key);
    struct hello_st* d = &s->client.hello;
    unsigned ret = HELLO_WRITE;

    // Leo bytes del socket y los mando
    size_t count;
    uint8_t* ptr = buffer_read_ptr(d->wb, &count);
    ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb)) {
            if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {

                // TODO: chquear si la auth esta prendida, si esta prendida transicionar al estado AUTH_READ
                ret = REQUEST_READ;
            } else {
                ret = ERROR;
            }
        }
    }

    return ret;
}

/** Librea los recursos al salir de HELLO_READ */
static void hello_read_close(const unsigned state, struct selector_key* key) {
    struct hello_st* d = &ATTACHMENT(key)->client.hello;
    hello_parser_close(&d->parser);
}

////////////////////////////////////////////////////////////////////////////////
//-----------------------------------REQUEST------------------------------------
////////////////////////////////////////////////////////////////////////////////

/** Inicializa las variables de los estados REQUEST*/
static void request_init(const unsigned state, struct selector_key* key) {
    struct socks5* s = ATTACHMENT(key);
    struct request_st* d = &s->client.request;
    d->rb = &s->read_buffer;
    d->wb = &s->write_buffer;
    d->parser.request = &d->request;
    d->status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
    request_parser_init(&d->parser);
    d->client_fd = &s->client_fd;
    d->origin_fd = &s->origin_fd;
    d->origin_addr = &s->origin_addr;
    d->origin_addr_len = &s->origin_addr_len;
    d->origin_domain = &s->origin_domain;
}

/**
 * Procesamiento del mensaje 'request', aca decidimos si cambiamos al estado REQUEST_CONNECTING o REQUEST_RESOLV
 * Si tenemos una direccion IP, intentamos establecer una conexion
 * Si tenemos que resolver el nombre (operacion bloqueante), disparamos la resolucion en un
 * thread que luego notificara al selector que ha terminado
 */
static unsigned request_process(struct selector_key* key, struct request_st* d) {
    struct socks5* s = ATTACHMENT(key);
    unsigned ret;
    pthread_t tid;
    struct selector_key* k;
    switch (d->request.cmd) {
        case SOCKS5_REQ_CMD_CONNECT: {
            // Esto mejoraria enormemente de haber usado sockaddr_storage en el request
            switch (d->request.dest_addr_type) {
                // Procesamiento para IPv4
                case SOCKS5_REQ_ADDRTYPE_IPV4: {
                    s->origin_domain = AF_INET;
                    d->request.dest_addr.ipv4.sin_port = d->request.dest_port;
                    s->origin_addr_len = sizeof(d->request.dest_addr.ipv4);
                    memcpy(&s->origin_addr, &d->request.dest_addr, sizeof(d->request.dest_addr.ipv4));
                    ret = request_connect_to_origin(key, d);
                    break;
                }
                // Procesamiento para IPv6
                case SOCKS5_REQ_ADDRTYPE_IPV6: {
                    s->origin_domain = AF_INET6;
                    d->request.dest_addr.ipv6.sin6_port = d->request.dest_port;
                    s->origin_addr_len = sizeof(d->request.dest_addr.ipv6);
                    memcpy(&s->origin_addr, &d->request.dest_addr, sizeof(d->request.dest_addr.ipv6));
                    ret = request_connect_to_origin(key, d);
                    break;
                }
                // Procesamiento para FQDN
                case SOCKS5_REQ_ADDRTYPE_DOMAIN: {
                    k = malloc(sizeof(*key));
                    if (k == NULL) {
                        ret = REQUEST_WRITE;
                        d->status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
                        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS)
                            ret = ERROR;
                    } else {
                        memcpy(k, key, sizeof(*k));
                        if (pthread_create(&tid, 0, request_resolv_blocking, k) != -1) {
                            ret = REQUEST_RESOLV;
                            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS)
                                ret = ERROR;
                        } else {
                            ret = REQUEST_WRITE;
                            d->status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
                            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS)
                                ret = ERROR;
                        }
                    }
                    break;
                }
                default: {
                    ret = REQUEST_WRITE;
                    d->status = SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED;
                    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                        ret = ERROR;
                        d->status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
                    }
                }
            }
            break;
        }
        case SOCKS5_REQ_CMD_BIND:
        case SOCKS5_REQ_CMD_ASSOCIATE:
        default:
            d->status = SOCKS5_STATUS_COMMAND_NOT_SUPPORTED;
            ret = REQUEST_WRITE;
            break;
    }
    return ret;
}

/**
 * Realiza la resolucion de DNS bloqueante
 * Una vez resuelto notifica al selector para que el evento
 * este disponible en la proxima iteracion
 */
static void* request_resolv_blocking(void* data) {
    struct selector_key* key = (struct selector_key*)data;
    struct socks5* s = ATTACHMENT(key);
    pthread_detach(pthread_self());
    s->origin_resolution = 0;

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,     // Allow IPv4 o IPv6
        .ai_socktype = SOCK_STREAM, // Datagram socket
        .ai_flags = AI_PASSIVE,     // For wildcard IP address
        .ai_protocol = 0,           // Any protocol
        .ai_canonname = NULL,
        .ai_addr = NULL,
        .ai_next = NULL,
    };

    char buff[7];
    snprintf(buff, sizeof(buff), "%d", ntohs(s->client.request.request.dest_port));

    if (getaddrinfo(s->client.request.request.dest_addr.fqdn, buff, &hints, &s->origin_resolution) < 0) {
        s->origin_resolution = NULL;
    }

    s->origin_resolution_current = s->origin_resolution;
    selector_notify_block(key->s, key->fd);
    free(data);

    return 0;
}

/** Intentamos establecer una conexion con el origin server */
static unsigned request_connect_to_origin(struct selector_key* key, struct request_st* d) {
    struct socks5* s = ATTACHMENT(key);
    enum socks5_response_status status = d->status;
    int* fd = d->origin_fd;
    bool error = false;

    // Para los logs
    char* tmp = (char*)malloc(INET_ADDRSTRLEN * sizeof(char));
    char* addr = inet_ntop(AF_INET, &d->request.dest_addr.ipv4.sin_addr, tmp, INET_ADDRSTRLEN);

    // Creamos el socket para conectarnos a origin
    *fd = socket(s->origin_domain, SOCK_STREAM, 0);
    if (*fd == -1) {
        error = true;
        goto finally;
    }
    // Lo seteamos como no bloqueante
    if (selector_fd_set_nio(*fd) == -1) {
        goto finally;
    }

    int aux = connect(*fd, (const struct sockaddr*)&s->origin_addr, s->origin_addr_len);
    if (aux == -1) {
        if (errno == EINPROGRESS) {
            log(INFO, "Connect to %s in progress", addr);
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
                error = true;
                goto finally;
            }
            if (selector_register(key->s, *fd, &socks5_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
                error = true;
                goto finally;
            }
            s->references += 1;
        } else {
            log(INFO, "Fail connecting to %s ", addr);
            status = errno_to_socks(errno);
            error = true;
            goto finally;
        }
    } else {
        // Estamos conectaos sin esperar --> no deberia ser posible
        abort();
    }

finally:
    if (error) {
        if (*fd != -1) {
            close(*fd);
            *fd = -1;
        }
    }
    d->status = status;
    return REQUEST_CONNECTING;
}

/** Lee todos los bytes del mensaje 'request' y inicia su proceso */
static unsigned request_read(struct selector_key* key) {
    struct request_st* d = &ATTACHMENT(key)->client.request;
    buffer* b = d->rb;
    unsigned ret = REQUEST_READ;
    bool error = false;

    size_t count;
    uint8_t* ptr = buffer_write_ptr(b, &count);
    ssize_t n = recv(key->fd, ptr, count, 0);

    if (n > 0) {
        buffer_write_adv(b, n);
        if (request_parser_consume(b, &d->parser, &error)) {
            ret = request_process(key, d);
        }
    } else {
        ret = ERROR;
    }
    return error ? ERROR : ret;
}

/** Procesa el resultado de la resolucion de nombres */
static unsigned request_resolv_done(struct selector_key* key) {
    struct socks5* s = ATTACHMENT(key);
    struct request_st* d = &s->client.request;

    if (s->origin_resolution == 0) {
        log(INFO, "Resolution failed");
        d->status = SOCKS5_STATUS_HOST_UNREACHABLE;
        return REQUEST_WRITE;
    } else {
        log(DEBUG, "Resolution success");
        s->origin_domain = s->origin_resolution->ai_family;
        s->origin_addr_len = s->origin_resolution->ai_addrlen;
        memcpy(&s->origin_addr, s->origin_resolution->ai_addr, s->origin_resolution->ai_addrlen);
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }

    return request_connect_to_origin(key, d);
}

////////////////////////////////////////////////////////////////////////////////
//----------------------------REQUEST CONNECT-----------------------------------
////////////////////////////////////////////////////////////////////////////////

/** Inicializa las variables de REQUEST_CONNECTING */
static void request_connecting_init(const unsigned state, struct selector_key* key) {
    struct socks5* s = ATTACHMENT(key);
    struct connecting* d = &s->orig.conn;
    d->client_fd = &s->client_fd;
    d->origin_fd = &s->origin_fd;
    d->status = &s->client.request.status;
    d->wb = &s->write_buffer;
}

/** La conexion ha sidpo establecida (o fallo) */
static unsigned request_connecting(struct selector_key* key) {
    int error;
    socklen_t len = sizeof(error);
    unsigned ret = REQUEST_CONNECTING;
    struct socks5* s = ATTACHMENT(key);
    struct request_st* d = &ATTACHMENT(key)->client.request;

    if (getsockopt(*s->orig.conn.origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        if (selector_set_interest(key->s, *s->orig.conn.client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
            s->client.request.status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
            ret = ERROR;
        } else if (error == 0) {
            log(INFO, "Connection to origin success");
            s->client.request.status = SOCKS5_STATUS_SUCCEED;
        } else {
            log(LOG_ERROR, "Connection to origin failed");
            s->client.request.status = errno_to_socks(error);
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
                ret = ERROR;
                s->client.request.status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
            }
        }

        int ocupped_bytes = request_parser_marshall(s->orig.conn.wb, *s->orig.conn.status, s->client.request.request.dest_addr_type,
                                                    s->client.request.request.dest_addr, s->client.request.request.dest_port);

        if (ocupped_bytes != -1) {
            ret = REQUEST_WRITE;
            if (selector_set_interest(key->s, *s->orig.conn.origin_fd, OP_READ) != SELECTOR_SUCCESS) {
                ret = ERROR;
            }
        } else {
            ret = ERROR;
        }
    }

    return ret;
}

/** Escribe todos los bytes de la respuesta al mensaje 'request' */
static unsigned request_write(struct selector_key* key) {
    struct socks5* s = ATTACHMENT(key);
    struct request_st* d = &s->client.request;
    unsigned ret = REQUEST_WRITE;
    buffer* b = d->wb;

    size_t count;
    uint8_t* ptr = buffer_read_ptr(b, &count);
    ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(b, n);
        if (!buffer_can_read(b)) {
            if (d->status == SOCKS5_STATUS_SUCCEED) {
                ret = COPY;
                if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                    ret = ERROR;
                }
            }
        }
    }

    return ret;
}

static void request_read_close(const unsigned state, struct selector_key* key) {
    struct request_st* d = &ATTACHMENT(key)->client.request;
    request_parser_close(&d->parser);
}

////////////////////////////////////////////////////////////////////////////////
//------------------------------------COPY--------------------------------------
////////////////////////////////////////////////////////////////////////////////

static void copy_init(const unsigned state, struct selector_key* key) {
    struct socks5* s = ATTACHMENT(key);
    struct copy* d = &s->client.copy;
    d->fd = &s->client_fd;
    d->rb = &s->read_buffer;
    d->wb = &s->write_buffer;
    d->duplex = OP_READ | OP_WRITE;
    d->other = &s->orig.copy;

    d = &s->orig.copy;
    d->fd = &s->origin_fd;
    d->rb = &s->write_buffer;
    d->wb = &s->read_buffer;
    d->duplex = OP_READ | OP_WRITE;
    d->other = &s->client.copy;
}

/**
 * Computa los intereses en base a la disponibilidad de los buffers.
 * La variable duplex nos permite saber si alguna via ya fue cerrada
 * Arranca OP_READ | OP_WRITE
 */
static fd_interest copy_compute_interests(fd_selector s, struct copy* d) {
    fd_interest ret = OP_NOOP;

    if (*d->fd != -1) {
        if (((d->duplex & OP_READ) && buffer_can_write(d->rb))) {
            ret |= OP_READ;
        }
        if ((d->duplex & OP_WRITE) && buffer_can_read(d->wb)) {
            ret |= OP_WRITE;
        }
        if (selector_set_interest(s, *d->fd, ret) != SELECTOR_SUCCESS) {
            abort();
        }
    }

    return ret;
}

/** Elige la estructura de copia correcta de cada fd (origin o client) */
static struct copy* copy_prt(struct selector_key* key) {
    struct copy* d = &ATTACHMENT(key)->client.copy;
    return *d->fd == key->fd ? d : d->other;
}

/** Lee bytes de un socket y los encola para ser escritos en otro socket */
static unsigned copy_read(struct selector_key* key) {
    struct copy* d = copy_prt(key);
    buffer* b = d->rb;
    unsigned ret = COPY;

    size_t size;
    uint8_t* ptr = buffer_write_ptr(b, &size);
    ssize_t n = recv(key->fd, ptr, size, 0);

    if (n <= 0) {
        shutdown(*d->fd, SHUT_RD);
        d->duplex &= ~OP_READ;
        if (*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_WR);
            d->other->duplex &= ~OP_WRITE;
        }
    } else {
        buffer_write_adv(b, n);
    }

    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);
    if (d->duplex == OP_NOOP) {
        ret = DONE;
    }

    return ret;
}

/** Escribe bytes encolados */
static unsigned copy_write(struct selector_key* key) {
    struct copy* d = copy_prt(key);
    buffer* b = d->wb;
    unsigned ret = COPY;

    size_t size;
    uint8_t* ptr = buffer_read_ptr(b, &size);
    ssize_t n = send(key->fd, ptr, size, MSG_NOSIGNAL);
    if (n == -1) {
        shutdown(*d->fd, SHUT_WR);
        d->duplex &= ~OP_WRITE;
        if (*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_RD);
            d->other->duplex &= ~OP_READ;
        }
    } else {
        buffer_read_adv(b, n);
    }

    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);

    if (d->duplex == OP_NOOP) {
        ret = DONE;
    }

    return ret;
}

////////////////////////////////////////////////////////////////////////////////
//----------------------------------USERPASS------------------------------------
////////////////////////////////////////////////////////////////////////////////

static void auth_init(const unsigned state, struct selector_key* key) {
    struct socks5* s = ATTACHMENT(key);
    struct auth_st* d = &s->client.auth;
    d->rb = &(s->read_buffer);
    d->wb = &(s->write_buffer);
    auth_parser_init(&d->parser);
    d->user_len = &d->parser.user_len;
    d->username = &d->parser.username;
    d->pass_len = &d->parser.pass_len;
    d->password = &d->parser.password;
}

static unsigned auth_process(struct auth_st* d) {
}

static unsigned auth_read(struct selector_key* key) {
}

static unsigned auth_write(struct selector_key* key) {
}
