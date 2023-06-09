#ifndef BUFFER_H_VelRDAxzvnuFmwEaR0ftrkIinkT
#define BUFFER_H_VelRDAxzvnuFmwEaR0ftrkIinkT

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h> // size_t, ssize_t

#define BUFFER_SIZE 4096

/**
 * Para esto se mantienen dos punteros, uno de lectura
 * y otro de escritura, y se provee funciones para
 * obtener puntero base y capacidad disponibles.
 *
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * |   |   |   |   |   |   |
 * +---+---+---+---+---+---+
 * ↑                       ↑
 * W=0                     limit=6
 *
 * Invariantes:
 *    R <= W <= limit
 *
 * Se quiere escribir en el buffer cuatro bytes.
 *
 * ptr + 0 <- buffer_write_ptr(b, &wbytes), wbytes=6
 * n = read(fd, ptr, wbytes)
 * buffer_write_adv(b, n = 4)
 *
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * | H | O | L | A |   |   |
 * +---+---+---+---+---+---+
 *                 ↑       ↑
 *                W=4      limit=6
 *
 * Quiero leer 3 del buffer
 * ptr + 0 <- buffer_read_ptr, wbytes=4
 * buffer_read_adv(b, 3);
 *
 *            R=3
 *             ↓
 * +---+---+---+---+---+---+
 * | H | O | L | A |   |   |
 * +---+---+---+---+---+---+
 *                 ↑       ↑
 *                W=4      limit=6
 *
 * Quiero escribir 2 bytes mas
 * ptr + 4 <- buffer_write_ptr(b, &wbytes=2);
 * buffer_write_adv(b, 2)
 *
 *            R=3
 *             ↓
 * +---+---+---+---+---+---+
 * | H | O | L | A |   | M |
 * +---+---+---+---+---+---+
 *                         ↑
 *                         limit=6
 *                         W=4
 * Compactación a demanda
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * | A |   | M |   |   |   |
 * +---+---+---+---+---+---+
 *             ↑           ↑
 *            W=3          limit=6
 *
 * Leo los tres bytes, como R == W, se auto compacta.
 *
 * R=0
 * ↓
 * +---+---+---+---+---+---+
 * |   |   |   |   |   |   |
 * +---+---+---+---+---+---+
 * ↑                       ↑
 * W=0                     limit=6
 */

typedef struct buffer buffer;
struct buffer {
    uint8_t* data;
    uint8_t* limit; // Límite superior del buffer (inmutable)
    uint8_t* read;  // Puntero de lectura
    uint8_t* write; // Puntero de escritura
};

/**
 * @brief Inicializa el buffer sin utilizar el heap
 * 
 */
void buffer_init(buffer* b, const size_t n, uint8_t* data);

/**
 * @return Puntero donde se pueden escribir hasta '*nbytes' 
 */
uint8_t* buffer_write_ptr(buffer* b, size_t* nbyte);
void buffer_write_adv(buffer* b, const ssize_t bytes);

uint8_t* buffer_read_ptr(buffer* b, size_t* nbyte);
void buffer_read_adv(buffer* b, const ssize_t bytes);

/**
 * @brief Obtiene un byte
 */
uint8_t buffer_read(buffer* b);

/**
 * @brief Escribe un byte
 */
void buffer_write(buffer* b, uint8_t c);

/**
 * @brief Compacta el buffer
 */
void buffer_compact(buffer* b);

/**
 * @brief Reinicia todos los punteros
 */
void buffer_reset(buffer* b);

/**
 * @brief Retorna true si hay bytes para leer del buffer
 */
bool buffer_can_read(buffer* b);

/**
 * @brief Retorna true si se pueden escribir bytes en el buffer
 * 
 */
bool buffer_can_write(buffer* b);

#endif
