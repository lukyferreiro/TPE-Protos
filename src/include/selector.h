#ifndef SELECTOR_H_W50GNLODsARolpHbsDsrvYvMsbT
#define SELECTOR_H_W50GNLODsARolpHbsDsrvYvMsbT

#include <stdbool.h>
#include <sys/time.h>

/**
 * selector.c - un muliplexor de entrada salida
 *
 * Un selector permite manejar en un único hilo de ejecución la entrada salida
 * de file descriptors de forma no bloqueante.
 *
 * Esconde la implementación final (select(2) / poll(2) / epoll(2) / ..)
 *
 * El usuario registra para un file descriptor especificando:
 *  1. un handler: provee funciones callback que manejarán los eventos de
 *     entrada/salida
 *  2. un interés: que especifica si interesa leer o escribir.
 *
 * Es importante que los handlers no ejecute tareas bloqueantes ya que demorará
 * el procesamiento del resto de los descriptores.
 *
 * Si el handler requiere bloquearse por alguna razón (por ejemplo realizar
 * una resolución de DNS utilizando getaddrinfo(3)), tiene la posiblidad de
 * descargar el trabajo en un hilo notificará al selector que el resultado del
 * trabajo está disponible y se le presentará a los handlers durante
 * la iteración normal. Los handlers no se tienen que preocupar por la
 * concurrencia.
 *
 * Dicha señalización se realiza mediante señales, y es por eso que al
 * iniciar la librería `selector_init' se debe configurar una señal a utilizar.
 *
 * Todos métodos retornan su estado (éxito / error) de forma uniforme.
 * Puede utilizar `selector_error' para obtener una representación human
 * del estado. Si el valor es `SELECTOR_IO' puede obtener información adicional
 * en errno(3).
 *
 * El flujo de utilización de la librería es:
 *  - iniciar la libreria `selector_init'
 *  - crear un selector: `selector_new'
 *  - registrar un file descriptor: `selector_register_fd'
 *  - esperar algún evento: `selector_iteratate'
 *  - destruir los recursos de la librería `selector_close'
 */
typedef struct fdselector* fd_selector;

/** Valores de retorno. */
typedef enum {
    SELECTOR_SUCCESS = 0, // Llamada exitosa
    SELECTOR_ENOMEM = 1,  // No pudimos alocar memoria
    SELECTOR_MAXFD = 2,   // Llegamos al límite de descriptores que la plataforma puede manejar
    SELECTOR_IARGS = 3,   // Illegal argument
    SELECTOR_FDINUSE = 4, // Descriptor que ya esta en uso
    SELECTOR_IO = 5,      // I/O error check errno
} selector_status;

/** Retorna una descripción humana del fallo */
const char* selector_error(const selector_status status);

/** Opciones de inicialización del selector */
struct selector_init {
    const int signal;               // Señal a utilizar para notificaciones internas
    struct timespec select_timeout; // Tiempo máximo de bloqueo durante `selector_iteratate'
};

/** Inicializa la librería */
selector_status selector_init(const struct selector_init* c);

/** Deshace la incialización de la librería */
selector_status selector_close(void);

/* Instancia un nuevo selector. returna NULL si no puede instanciar  */
fd_selector selector_new(const size_t initial_elements);

/** Destruye un selector creado por _new. Tolera NULLs */
void selector_destroy(fd_selector s);

/**
 * Intereses sobre un file descriptor (quiero leer, quiero escribir, …)
 *
 * Son potencias de 2, por lo que se puede requerir una conjunción usando el OR
 * de bits.
 *
 * OP_NOOP es útil para cuando no se tiene ningún interés.
 */
typedef enum {
    OP_NOOP = 0,
    OP_READ = 1 << 0,
    OP_WRITE = 1 << 2,
} fd_interest;

/** Quita un interés de una lista de intereses */
#define INTEREST_OFF(FLAG, MASK) ((FLAG) & ~(MASK))

/** Argumento de todas las funciones callback del handler */
struct selector_key {
    fd_selector s; // El selector que dispara el evento
    int fd;        // El file descriptor en cuestión
    void* data;    // Dato provisto por el usuario en cuestion
};

/** Manejador de los diferentes eventos */
typedef struct fd_handler {
    void (*handle_read)(struct selector_key* key);
    void (*handle_write)(struct selector_key* key);
    void (*handle_block)(struct selector_key* key);
    // Se llama cuando se desregistra el fd
    // Seguramente deba liberar los recusos alocados en data.
    void (*handle_close)(struct selector_key* key);
} fd_handler;

/**
 * Registra en el selector `s' un nuevo file descriptor `fd'.
 *
 * Se especifica un `interest' inicial, y se pasa handler que manejará
 * los diferentes eventos. `data' es un adjunto que se pasa a todos
 * los manejadores de eventos.
 *
 * No se puede registrar dos veces un mismo fd.
 *
 * @return 0 si fue exitoso el registro.
 */
selector_status selector_register(fd_selector s, const int fd, const fd_handler* handler,
                                  const fd_interest interest, void* data);

/**
 * Desregistra un file descriptor del selector
 */
selector_status selector_unregister_fd(fd_selector s, const int fd);

/** Permite cambiar los intereses para un file descriptor */
selector_status selector_set_interest(fd_selector s, int fd, fd_interest i);

/** Permite cambiar los intereses para un file descriptor */
selector_status selector_set_interest_key(struct selector_key* key, fd_interest i);

/**
 * Se bloquea hasta que hay eventos disponible y los despacha.
 * Retorna luego de cada iteración, o al llegar al timeout.
 */
selector_status selector_select(fd_selector s);

/**
 * Método de utilidad que activa O_NONBLOCK en un fd.
 *
 * Retorna -1 ante error, y deja detalles en errno.
 */
int selector_fd_set_nio(const int fd);

/** Notifica que un trabajo bloqueante terminó */
selector_status selector_notify_block(fd_selector s, const int fd);

#endif
