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

static const unsigned max_pool = 50;    // Tamaño maximo
static unsigned pool_size = 0;          // Tamaño actual
static struct socks5* pool = 0;         // Pool propiamente dicho

//-----------------------------------------------------------------------------
static const struct state_definition* socks5_describe_states(void);

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
static void request_init(cont unsigned state, struct selector_key* key);
static unsigned request_process(struct selector_key* key, const struct hello_st* d);
static unsigned request_read(struct selector_key* key);
//-----------------------------------------------------------------------------

static const struct fd_handler socks5_handler = {
    .handle_read = socksv5_read,
    .handle_write = socksv5_write,
    .handle_close = socksv5_close,
    .handle_block = socksv5_block,
};

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
     *   - REQUEST_RESOLV       si requiete resolver un nombre DNS
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

    /**
     * Si el mecanismo de autenticacion es [05 02]
     */
    USERPASS_READ,
    USERPASS_WRITE,

    // Estados terminales
    DONE,
    ERROR,
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
        .on_arrival = request_connection_init,
        .on_write_ready = request_connecting,
    },
    {
        .state = COPY,
        .on_arrival = copy_init,
        .on_departure = copy_read,
        .on_read_ready = copy_write,
    },
    {
        .state = USERPASS_READ
        // ... ??
    },
    {
        .state = USERPASS_WRITE
        // ... ??
    },
    {.state = DONE},
    {.state = ERROR}};

/** Usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    buffer* rb;                 // Buffer de escritura utilizado para I/O
    buffer* wb;                 // Buffer de lectura utilizado para I/O
    struct hello_parser parser; // TODO hacer el parser del hello
    uint8_t method;             // El metodo de autenticacion seleccionado
};

/** Usado por REQUEST_READ, REQUEST_WRITE, REQUEST_RESOLV */
struct request_st {
    buffer* rb; // Buffer de escritura utilizado para I/O
    buffer* wb; // Buffer de lectura utilizado para I/O

    struct request request;       // TODO hacer la struct request
    struct request_parser parser; // TODO hacer el parser del request

    enum socks5_response_status status; // El resumen de la respuesta a enviar

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

////////////////////////////////////////////////////////////////////////////////
//-----------------------------------SOCKS5-------------------------------------
////////////////////////////////////////////////////////////////////////////////

static const struct state_definition* socks5_describe_states(void) {
    return client_statbl;
}

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
        log(ERROR, "Failed to create socks");
        goto finally;
    }

    memset(ret, 0x00, sizeof(*ret));

    ret->origin_fd = -1;
    ret->client_fd = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);
    ret->stm.initial = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states = sock5_describe_states();

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
        free(s);
    }
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
            if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}

void socksv5_passive_accept(struct selector_key* key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct socks5* state = NULL;
    const int client = accept(key->fd, (struct sockaddr*)&client_addr, &client_addr_len);

    if (client == -1) {
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1) {
        goto fail;
    }

    state = socks5_new(client);
    if (state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }

    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if (SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler, OP_READ, state)) {
        goto fail;
    }
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
    if (SOCKS_HELLO_NOAUTHENTICATION_REQUIRED == method) {
        *selected = method;
    }
}

/** Inicializa las variables de los estados HELLO_… */
static void hello_read_init(const unsigned state, struct selector_key* key) {
    struct hello_st* d = &ATTACHMENT(key)->client.hello;
    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    d->parser.data = &d->method;
    d->parser.on_authentication_method = on_hello_method, hello_parser_init(&d->parser);
}

/** Lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned hello_read(struct selector_key* key) {
    struct hello_st* d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_READ;
    bool error = false;
    size_t count;
    uint8_t* ptr = buffer_write_ptr(d->rb, &count);
    ssize_t n = recv(key->fd, ptr, count, 0);

    if (n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if (hello_is_done(st, 0)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
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

/** Procesamiento del mensaje `hello' */
static unsigned hello_process(const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;
    uint8_t m = d->method;
    const uint8_t r = (m == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) ? 0xFF : 0x00;

    if (-1 == hello_marshall(d->wb, r)) {
        ret = ERROR;
    }
    if (SOCKS_HELLO_NO_ACCEPTABLE_METHODS == m) {
        ret = ERROR;
    }

    return ret;
}

static unsigned hello_write(struct selector_key* key) {
    struct hello_st* d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_WRITE;
    size_t count;
    uint8_t* ptr = buffer_read_ptr(d->wb, &count);
    ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
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
static void request_init(cont unsigned state, struct selector_key* key) {
    struct request_st* d = &ATTACHMENT(key)->client.request;
    d->rb = &ATTACHMENT(key)->read_buffer;
    d->wb = &ATTACHMENT(key)->write_buffer;
    d->parser.request = &d->request;
    d->status = status_general_SOCK5_server_failure;
    request_parser_init(&d->parser);
    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;
    d->origin_addr = &ATTACHMENT(key)->origin_addr;
    d->origin_addr_len = &ATTACHMENT(key)->origin_addr_len;
    d->origin_domain = &ATTACHMENT(key)->origin_domain;
}

/** Procesamiento del mensaje `request' */
static unsigned request_process(struct selector_key* key, const struct hello_st* d) {
    //...
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
        int st = request_consume(b, &d->parser, &error);
        if (request_is_done(st, 0)) {
            ret = request_proccess(key, d);
        }
    } else {
        ret = ERROR;
    }
    return error ? ERROR : ret;
}