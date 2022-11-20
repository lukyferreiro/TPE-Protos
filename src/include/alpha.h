#ifndef __ALPHA_H_
#define __ALPHA_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_DATAGRAM_SIZE 65507 // Espacio disponible descontando el header UDP segun wikipedia, bastante mas de lo que necesitamos creo
#define ALPHA_REQUEST_HEADER_SIZE 9
#define ALPHA_RESPONSE_HEADER_SIZE 6
#define ALPHA_REQUEST_ID_SIZE 2
#define ERROR -1
#define OK 0
#define USER_PAGE_SIZE 25 // Cantidad de usuarios es lo unico que no entraria en un unico paquete UDP
#define COMMANDS_SIZE 12

typedef enum alpha_packet_type {
    ALPHA_REQUEST,
    ALPHA_RESPONSE
} alpha_packet_type;

typedef enum alpha_commands {
    GET_LIST,
    GET_HIST_CONN,
    GET_CONC_CONN,
    GET_BYTES_TRANSF,
    GET_IS_SNIFF_ENABLED,
    GET_IS_AUTH_ENABLED,
    POST_ADD_USER,
    POST_DEL_USER,
    POST_ENABLE_SNIFF,
    POST_DISABLE_SNIFF,
    POST_ENABLE_AUTH,
    POST_DISABLE_AUTH
} alpha_commands;

typedef enum alpha_version {
    ALPHA_V1 = 1
} alpha_version;

// codigos de respuesta del protocolo
typedef enum alpha_status_code {
    SC_OK,
    SC_INVALID_VERSION,
    SC_BAD_CREDENTIALS,
    SC_INVALID_COMMAND,
    SC_INVALID_ARGUMENT,
    SC_SERVER_IS_FULL,
    SC_INVALID_USER_IS_REGISTERED,
    SC_USER_NOT_FOUND,
    SC_INTERNAL_SERVER_ERROR,
} alpha_status_code;

// Tipos de dato que se podrían enviar en el protocolo
typedef enum alpha_data {
    EMPTY_DATA,
    UINT_8_DATA,
    UINT_16_DATA,
    UINT_32_DATA,
    STRING_DATA
} alpha_data;

typedef union current_alpha_data {
    uint8_t alpha_uint8;
    uint16_t alpha_uint16;
    uint32_t alpha_uint32;
    char string[MAX_DATAGRAM_SIZE - ALPHA_REQUEST_HEADER_SIZE];
} current_alpha_data;

typedef struct alpha_req {
    alpha_version alpha_version;
    unsigned command;
    uint16_t req_id;
    uint32_t token;
    current_alpha_data data;
} alpha_req;

typedef struct alpha_res {
    alpha_version alpha_version;
    alpha_status_code status;
    unsigned command;
    uint16_t res_id;
    current_alpha_data data;
} alpha_res;

// Metodos que nos dirán el tipo de dato a devolver segun el comando que se le pase
alpha_data cmd_to_req_data_type(unsigned alpha_cmd);
alpha_data cmd_to_res_data_type(unsigned alpha_cmd);

// Metodos que convertirán el buffer udp de entrada a una struct de nuestro protocolo
int udp_to_alpha_req(char* raw_buffer, struct alpha_req* request);
int udp_to_alpha_res(char* raw_buffer, struct alpha_res* response);

// Metodos que transformaran nuestra
int alpha_req_to_packet(char* output, struct alpha_req* input, int* size);
int alpha_res_to_packet(char* output, struct alpha_res* input, int* size);

// Metodo para reportar errores
char* alpha_error_report(alpha_status_code status_code);

#endif