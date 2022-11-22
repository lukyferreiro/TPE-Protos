// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "logger.h"
#include "socks_utils.h"
#include <stdio.h>
#include <time.h>

#define MAX_DATE 21


LOG_LEVEL current_level = DEBUG;

void get_date_buff(char* buff) {
    time_t now = time(NULL);
    struct tm* time_info = localtime(&now);
    strftime(buff, MAX_DATE, "%FT%T", time_info);
}

void setLogLevel(LOG_LEVEL newLevel) {
    if (newLevel >= DEBUG && newLevel <= FATAL)
        current_level = newLevel;
}

char* levelDescription(LOG_LEVEL level) {
    static char* description[] = {"DEBUG", "INFO", "ERROR", "FATAL"};
    if (level < DEBUG || level > FATAL)
        return "";
    return description[level];
}

void logger(LOG_LEVEL level, const char* fmt, ...) {
    if (level >= current_level) {
        fprintf(stderr, "%s: ", levelDescription(level));
        va_list arg;
        va_start(arg, fmt);
        vfprintf(stderr, fmt, arg);
        va_end(arg);
        fprintf(stderr, "\n");
    }
    if (level == FATAL)
        exit(1);
}

void log_debug(const char* fmt, ...) {
#ifdef IS_DEBUG
    fprintf(stderr, "DEBUG: ");
    va_list arg;
    va_start(arg, fmt);
    vfprintf(stderr, fmt, arg);
    va_end(arg);
    fprintf(stderr, "\n");
#endif
}

void sniffer_logger(char* username, char* password) {
    char date[MAX_DATE];
    get_date_buff(date);
    logger(INFO, "%s\t Sniffed credentials: %s:%s\n", date, username, password);
    //free(date);
}
