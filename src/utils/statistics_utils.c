#include "statistics_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct socks5_stats socks5_stats;

void init_stats(struct socks5_stats *socks5_stats) {
    memset(socks5_stats, 0, sizeof(*socks5_stats));
}

void inc_current_connections(void) {
    socks5_stats.conc_conn++;
    socks5_stats.his_conn++;
}

void dec_current_connections(void) {
    if (socks5_stats.conc_conn > 0) {
        socks5_stats.conc_conn--;
    }
}

void add_bytes_transferred(uint32_t bytes) {
    socks5_stats.bytes_transfered += bytes;
}

void inc_nusers(void) { socks5_stats.nusers++; }
