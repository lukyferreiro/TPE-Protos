#ifndef __STATISTICS_H_
#define __STATISTICS_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct socks5_stats {
    uint32_t bytes_transfered;
    uint32_t his_conn;
    uint16_t conc_conn;
    int nusers;
};

/**
 * @brief Inicializa la estructura de estadisticas 
 */
void init_stats(struct socks5_stats* socks5_stats);

/**
 * @brief Incrementa la cantidad de conexoines concurrentes
 */
void inc_current_connections(void);

/**
 * @brief Decrementa la cantidad de conexiones concurrentes
 */
void dec_current_connections(void);

/**
 * @brief Suma los bytes recibidos como parametro en la estructura 
 */
void add_bytes_transferred(uint32_t bytes);

/**
 * @brief Incrementa la cantidad de usuarios
 */
void inc_nusers(void);

#endif