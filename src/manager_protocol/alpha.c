#include "alpha.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

static int get_packet_size(alpha_packet_type alpha_packet_type, unsigned alpha_cmd, char *data)

static void read_data(current_alpha_data *output, alpha_data alpha_data, char *input);

static void alpha_data_to_buffer(current_alpha_data input, alpha_data alpha_data, char *output);


//Tipo de dato a devolver segun el comando y tipo de response
alpha_data cmd_to_req_data_type(unsigned alpha_cmd){
    switch (alpha_cmd) {
        case GET_CMD_LIST:
            return STRING_DATA;

        case GET_CMD_HIST_CONN:

        case GET_CMD_BYTES_TRANSF:
            return UINT_32_DATA;

        case GET_CMD_CONC_CONN:
            return UINT_16_DATA;

        case GET_CMD_IS_SNIFFING_ENABLED:

        case GET_CMD_IS_AUTH_ENABLED:

        case GET_CMD_USER_PAGE_SIZE:
            return UINT_8_DATA;

        case POST_CMD_ADD_USER:

        case POST_CMD_DEL_USER:

        case POST_CMD_TOGGLE_SNIFFING:

        case POST_CMD_TOGGLE_AUTH:

        default:

            return EMPTY_DATA;
        }
}

//Tipo de dato a devolver segun el comando y tipo de response
alpha_data cmd_to_res_data_type(unsigned alpha_cmd);{
    switch (alpha_cmd) {
        case GET_CMD_LIST:
            return STRING_DATA;
            
        case GET_CMD_HIST_CONN:
        
        case GET_CMD_BYTES_TRANSF:
            return UINT_32_DATA;

        case GET_CMD_CONC_CONN:
            return UINT_16_DATA;

        case GET_CMD_IS_SNIFFING_ENABLED:

        case GET_CMD_IS_AUTH_ENABLED:

        case GET_CMD_USER_PAGE_SIZE:
            return UINT_8_DATA;

        case POST_CMD_ADD_USER:

        case POST_CMD_DEL_USER:

        case POST_CMD_TOGGLE_SNIFFING:

        case POST_CMD_TOGGLE_AUTH:
    default:
        return EMPTY_DATA;
    }
}

int udp_to_alpha_req(char *raw_buffer, struct alpha_req* request) {
    if (raw == NULL || request == NULL) {
        return -1;
    }

    
    request->alpha_version = *((uint8_t *)raw);
    raw_buffer += sizeof(uint8_t);

   
    request->current_alpha_cmd = ntohs(*((uint16_t *)raw));
    raw_buffer += sizeof(uint16_t);

    
    request->req_id = ntohs(*((uint16_t *)raw));
    raw_buffer += sizeof(uint16_t);

    /*  token */
    request->token = ntohl(*((uint32_t *)raw));
    raw_buffer += sizeof(uint32_t);

    //Guardo en la struct el buffer
    read_data(&request->data, cmd_to_req_data_type(request->command), raw_buffer);

    return 0;
}

int udp_to_alpha_res(char *raw, alpha_res *response){
    if (raw == NULL || response == NULL) {
        return ERROR;
    }

    
    response->alpha_version = *((uint8_t *)raw);
    raw += sizeof(uint8_t);

    response->alpha_status_code = *((uint8_t *)raw);
    raw += sizeof(uint8_t);


    response->command = ntohs(*((uint16_t *)raw));
    raw += sizeof(uint16_t);

    response->req_id = ntohs(*((uint16_t *)raw));
    raw += sizeof(uint16_t);

    if (response->alpha_status_code == SC_OK)
        read_data(&response->current_alpha_data, cmd_to_resp_data_type(response->command), raw);

    return 0;
}


static void read_data(current_alpha_data *output, alpha_data alpha_data, char *input){
    switch (alpha_data) {
    case UINT_8_DATA:
        output->alpha_uint8 = *((uint8_t *)input);
        break;
    case UINT_16_DATA:
        output->alpha_uint16 = ntohs(*((uint16_t *)input));
        break;
    case UINT_32_DATA:
        output->alpha_uint32 = ntohl(*((uint32_t *)input));
        break;
    case STRING_DATA:
        strcpy(output->string, input);
        break;
    case EMPTY_DATA:
    default:
        output->string[0] = 0;
    }
}

int alpha_req_to_packet(char* output, struct alpha_req * input, int* size){
    if (output == NULL || input == NULL) {
        return ERROR;
    }

    int aux;
    *size =
       get_packet_size(ALPHA_REQUEST, input->command,
                        input->data.string);
    char *buffer_p = output;

    //Cargo el header
    aux = input->alpha_version;
    memcpy(buffer_p, &aux, sizeof(uint8_t));
    buffer_p += sizeof(uint8_t);

    aux = htons(input->command);
    memcpy(buffer_p, &aux, sizeof(uint16_t));
    buffer_p += sizeof(uint16_t);

    aux = htons(input->req_id);
    memcpy(buffer_p, &aux, sizeof(uint16_t));
    buffer_p += sizeof(uint16_t);

    aux = htonl(input->token);
    memcpy(buffer_p, &aux, sizeof(uint32_t));
    buffer_p += sizeof(uint32_t);

    alpha_data_to_buffer(
        input->data,
        cmd_to_req_data_type(input->command),
        buffer_p);

    return 0;
}

int alpha_res_to_packet(char* output, struct alpha_res * input, int* size){
    if (output == NULL || input == NULL) {
        return -1;
    }

    int aux;
    *size =
        get_packet_size(ALPHA_RESPONSE, input->command,
                        input->data.string);
    char *buffer_p = output;

    aux = input->alpha_version;
    memcpy(buffer_p, &aux, sizeof(uint8_t));
    buffer_p += sizeof(uint8_t);

    aux = input->status;
    memcpy(buffer_p, &aux, sizeof(uint8_t));
    buffer_p += sizeof(uint8_t);

    aux = htons(input->command);
    memcpy(buffer_p, &aux, sizeof(uint16_t));
    buffer_p += sizeof(uint16_t);

    aux = htons(input->req_id);
    memcpy(buffer_p, &aux, sizeof(uint16_t));
    buffer_p += sizeof(uint16_t);

    if (input->status == SC_OK)
        alpha_data_to_buffer(
            input->data,
            cmd_to_res_data_type(input->command),
            buffer_p);

    return 0;
}


static int get_packet_size(alpha_packet_type alpha_packet_type, unsigned command, char *data) {
    size_t size = 0;
    alpha_data alpha_data;
    if (alpha_packet_type == ALPHA_REQUEST) {
        size += ALPHA_REQUEST_HEADER_SIZE;
        alpha_data = cmd_to_req_data_type(command);
    } else {
        size += ALPHA_RESPONSE_HEADER_SIZE;
        alpha_data = cmd_to_resp_data_type(command);
    }

    switch (alpha_data) {
        case UINT_8_DATA:
            size += sizeof(uint8_t);
            break;
        case UINT_16_DATA:
            size += sizeof(uint16_t);
            break;
        case UINT_32_DATA:
            size += sizeof(uint32_t);
            break;
        case STRING_DATA:
            size += (data != NULL) ? strlen(data) : 0;
            break;
        default:
            break;
    }

    return size;
}

static void alpha_data_to_buffer(current_alpha_data input, alpha_data alpha_data, char *output){
    int aux;
    switch (alpha_data) {
    case UINT_8_DATA:
        aux = input.alpha_uint8;
        memcpy(output, &aux, sizeof(uint8_t));
        break;
    case UINT_16_DATA:
        aux = htons(input.alpha_uint16);
        memcpy(output, &aux, sizeof(uint16_t));
        break;
    case UINT_32_DATA:
        aux = htonl(input.alpha_uint32);
        memcpy(output, &aux, sizeof(uint32_t));
        break;
    case STRING_DATA:
        strcpy(output, input.string);
        break;
    case EMPTY_DATA:
    default:
        break;
    }
}