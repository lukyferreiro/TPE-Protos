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

void init_stats(struct socks5_stats* socks5_stats);
void inc_current_connections(void);
void dec_current_connections(void);
void add_bytes_transferred(uint32_t bytes);
void inc_nusers(void);

#endif