#include "alpha.h"
#include "args.h"
#include "logger.h"
#include "netutils.h"
#include "socks_utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#define BUFFER_SIZE 4096
#define USER_INPUT_SIZE 100
#define TIMEOUT_SEC 5
#define MAX_ATTEMPS 3
#define CANT_COMMANDS 12

static bool done = false;
static struct alpha_req alpha_manager_req;
static struct alpha_res alpha_manager_res;
uint16_t id_counter;
uint32_t token;

static void sigterm_handler(const int signal) {
    printf("Signal %d, cleaning up and exiting\n", signal);
    done = true;
}

static void help();
static void print_white_spaces(int start, int end);
static bool header_builder_with_param(struct alpha_req* alpha_req, unsigned cmd, char* param);
static bool header_builder_no_param(struct alpha_req* alpha_req, unsigned cmd);
static void response_handler(struct alpha_req alpha_req, struct alpha_res alpha_res, char* message);

typedef struct alpha_shell_command {
    char* name;
    char* param_name;
    char* description;
    char* on_success_message;
    size_t nparams;
} alpha_shell_command;

// Arreglo de comandos disponibles con cantidad de parametros aceptados y descripcion
alpha_shell_command alpha_shell_commands[] = {
    {.name = "list",
     .param_name = "<page_number>",
     .nparams = 1,
     .description = "Returns the specified page of the list of users registered on the server",
     .on_success_message = "Users"},
    {.name = "hist",
     .param_name = "",
     .nparams = 0,
     .description = "Number of historic connections over the server",
     .on_success_message = "Number of historic connections"},
    {.name = "conc",
     .param_name = "",
     .nparams = 0,
     .description = "Number of concurrent connections over the server",
     .on_success_message = "Number of concurrent connections"},
    {.name = "bytes",
     .param_name = "",
     .nparams = 0,
     .description = "Amount of bytes transfered over the server",
     .on_success_message = "Amount of bytes transfered"},
    {.name = "checksniff",
     .param_name = "",
     .nparams = 0,
     .description = "Delivers status of the password disector over the server",
     .on_success_message = "POP3 credential sniffer status"},
    {.name = "checkauth",
     .param_name = "",
     .nparams = 0,
     .description = "Delivers status of authentication over the server",
     .on_success_message = "Authentication status"},
    {.name = "add",
     .param_name = "user:pass",
     .nparams = 1,
     .description = "Run this to add a user",
     .on_success_message = "User added successfully"},
    {.name = "del",
     .param_name = "user",
     .nparams = 1,
     .description = "Run this to delete a user",
     .on_success_message = "User deleted successfully"},
    {.name = "sniff-on",
     .param_name = "",
     .nparams = 0,
     .description = "Run this to enable POP3 credential sniffer over the server",
     .on_success_message = "POP3 credential sniffer enabled!"},
    {.name = "sniff-off",
     .param_name = "",
     .nparams = 0,
     .description = "Run this to disable POP3 credential sniffer over the server",
     .on_success_message = "POP3 credential sniffer disabled!"},
    {.name = "auth-on",
     .param_name = "",
     .nparams = 0,
     .description = "Run this to enable authentication over the server",
     .on_success_message = "Authentication enabled!"},
    {.name = "auth-off",
     .param_name = "",
     .nparams = 0,
     .description = "Run this to disable authentication over the server",
     .on_success_message = "Authentication disabled!"},
};

// Shell que recibe los comandos
int main(const int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: ./alpha_manager <addr> <port> \n");
        exit(EXIT_FAILURE);
    }

    char* environment_token = getenv("ALPHA_TKN");
    if (environment_token == NULL) {
        fprintf(stderr, "Check that the environment token %s exists\n", ALPHA_TKN);
        exit(EXIT_FAILURE);
    }
    if (strlen(environment_token) < MIN_TOKEN_SIZE || strlen(environment_token) > MAX_TOKEN_SIZE) {
        fprintf(stderr, "Token must be between %d and %d characters\n", MIN_TOKEN_SIZE, MAX_TOKEN_SIZE);
        exit(EXIT_FAILURE);
    }
    if(!isNumber(environment_token)) {
        fprintf(stderr, "%s must be a numeric token\n", ALPHA_TKN);
        exit(EXIT_FAILURE);
    }

    token = (uint32_t) strtoul(environment_token, NULL, 10);

    // Configuración general a donde se envía la información
    int sockfd;
    int valid_param = false;
    int port;
    int ip_type = ADDR_IPV4;
    int i_command;
    struct sockaddr_in serv_addr;
    struct sockaddr_in6 serv_addr6;
    char buffer_in[BUFFER_SIZE];
    char buffer_out[BUFFER_SIZE];
    char user_input[USER_INPUT_SIZE];

    memset(&serv_addr, 0, sizeof(serv_addr));
    memset(&serv_addr6, 0, sizeof(serv_addr6));

    if ((port = htons(atoi(argv[2]))) <= 0) {
        fprintf(stderr, "ERROR: Invalid port\n");
        exit(EXIT_FAILURE);
    }

    // Inicializo el puerto según la dirección ip que me mandaron
    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr.s_addr) > 0) {
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = port;
        ip_type = ADDR_IPV4;
    } else if (inet_pton(AF_INET6, argv[1], &serv_addr6.sin6_addr) > 0) {
        serv_addr6.sin6_family = AF_INET6;
        serv_addr6.sin6_port = port;
        ip_type = ADDR_IPV6;
    }

    // Creo el socket según el tipo de IP
    if ((sockfd = socket(ip_type == ADDR_IPV4 ? AF_INET : AF_INET6, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "ERROR: Cannot create socket\n");
        exit(EXIT_FAILURE);
    }

    // Registrar sigterm es útil para terminar el programa normalmente.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);
    signal(SIGSTOP, sigterm_handler);
    signal(SIGQUIT, sigterm_handler);

    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        fprintf(stderr, "ERROR: Failed setsockopt in Alpha\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    while (!done) {
        char* command = NULL;
        char* param = NULL;
        printf("Alpha manager client $ ");

        memset(user_input, 0, USER_INPUT_SIZE);
        char* aux = fgets(user_input, USER_INPUT_SIZE, stdin);
        if (aux == NULL) {
            printf("\nInput is null\n");
            done = true;
        }

        if (user_input[0] == 0) {
            printf("No command specified.\n");
            continue;
        }  

        user_input[strcspn(user_input, "\r\n")] = 0;
        command = user_input;
        param = strchr(user_input, ' ');
        if (param != NULL) {
            *param++ = 0;
        }

        if (strcmp(command, "help") == 0) {
            help();
            continue;
        }

        for (i_command = 0; i_command < COMMANDS_SIZE; i_command++) {
            if (strcmp(command, alpha_shell_commands[i_command].name) == 0) {
                if (alpha_shell_commands[i_command].nparams == 0) {
                    if (param == NULL) {
                        valid_param = header_builder_no_param(&alpha_manager_req, i_command);
                    } else {
                        valid_param = false;
                    }
                }
                if (alpha_shell_commands[i_command].nparams > 0) {
                    if (param != NULL) {
                        valid_param = header_builder_with_param(&alpha_manager_req, i_command, param);
                    } else {
                        valid_param = false;
                    }
                }
                break;
            }
        }

        // Validaciones si no existia comando o si le faltaba un parámetro
        if (i_command == COMMANDS_SIZE) {
            printf("Invalid command.\n");
            continue;
        }

        if (valid_param == false) {
            printf("Invalid parameter\n");
            printf("Command: %s\t Usage: %s %s\t description: %s\n",
                   alpha_shell_commands[i_command].name, alpha_shell_commands[i_command].name,
                   alpha_shell_commands[i_command].param_name, alpha_shell_commands[i_command].description);
            continue;
        }

        // Si el comando era válido, hago el request al server
        int req_size;
        ssize_t resp_size;
        socklen_t len;

        memset(buffer_in, 0, BUFFER_SIZE);
        memset(buffer_out, 0, BUFFER_SIZE);

        if (alpha_req_to_packet(buffer_out, &alpha_manager_req, &req_size) < 0) {
            fprintf(stderr, "Error building request packet");
        }

        // Envio el request al server y luego recibo la respuesta segun el tipo de IP
        if (ip_type == ADDR_IPV4) {
            sendto(sockfd, buffer_out, req_size, MSG_CONFIRM, (const struct sockaddr*)&serv_addr, sizeof(serv_addr));
            resp_size = recvfrom(sockfd, (char*)buffer_in, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr*)&serv_addr, &len);
        } else {
            sendto(sockfd, buffer_out, req_size, MSG_CONFIRM, (const struct sockaddr*)&serv_addr6, sizeof(serv_addr6));
            resp_size = recvfrom(sockfd, (char*)buffer_in, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr*)&serv_addr6, &len);
        }

        // Timeout
        if (resp_size < 0) {
            printf("Destination unreachable.\n");
            continue;
        }

        // Handleo de la response del server
        if (udp_to_alpha_res(buffer_in, &alpha_manager_res) < 0) {
            fprintf(stderr, "Error converting raw packet to response");
            continue;
        }

        response_handler(alpha_manager_req, alpha_manager_res, alpha_shell_commands[i_command].on_success_message);
    }
}

void help() {
    printf("|     NAME   |        SYNOPSIS     |                               "
           "DESCRIPTION                                |\n");
    printf("|------------+---------------------+--------------------------------"
           "------------------------------------------|\n");
    for (int i = 0; i < CANT_COMMANDS; i++) {
        printf("| ");
        printf("%s", alpha_shell_commands[i].name);
        print_white_spaces(strlen(alpha_shell_commands[i].name), 10);

        printf(" | ");
        printf("%s", alpha_shell_commands[i].param_name);
        print_white_spaces(strlen(alpha_shell_commands[i].param_name), 19);

        printf(" | ");
        printf("%s", alpha_shell_commands[i].description);
        print_white_spaces(strlen(alpha_shell_commands[i].description), 72);
        printf(" | \n");
    }
}

static void print_white_spaces(int start, int end) {
    for (int j = start; j < end; j++) {
        printf(" ");
    }
}

static bool header_builder_no_param(struct alpha_req* alpha_req, unsigned cmd) {
    alpha_req->alpha_version = ALPHA_V1;
    alpha_req->command = cmd;
    alpha_req->req_id = id_counter++;
    alpha_req->token = token;
    return true;
}

static bool header_builder_with_param(struct alpha_req* alpha_req, unsigned cmd, char* param) {
    int aux;
    switch (cmd) {
        case GET_LIST:
            aux = atoi(param);
            if (aux <= 0)
                return false;
            alpha_req->data.alpha_uint8 = aux;
            break;

        case POST_ADD_USER:
            // Parametros tbd
            if (*param == USER_PASSWORD_DELIMETER)
                return false;
            char* temp = strchr(param, USER_PASSWORD_DELIMETER);
            if (temp == NULL || strlen(temp) > MAX_LEN_USERS || *(temp++) == '\0' ||
                strlen(temp) > MAX_LEN_USERS)
                return false;
            strcpy(alpha_req->data.string, param);
            break;

        case POST_DEL_USER:
            if (param == NULL || strlen(param) > MAX_LEN_USERS)
                return false;
            strcpy(alpha_req->data.string, param);
            break;

        default:
            return false;
            break;
    }

    return header_builder_no_param(alpha_req, cmd);
}

void response_handler(struct alpha_req alpha_req, struct alpha_res alpha_res, char* message) {
    if (alpha_req.req_id != alpha_res.res_id) {
        printf("Error: response id != request id.\n");
        return;
    }

    if (alpha_res.status != SC_OK) {
        printf("Error: %s.\n", alpha_error_report(alpha_res.status));
        return;
    }

    switch (cmd_to_res_data_type(alpha_res.command)) {
        case UINT_8_DATA:
            printf("%s: %d", message, alpha_res.data.alpha_uint8);
            break;
        case UINT_16_DATA:
            printf("%s: %d", message, alpha_res.data.alpha_uint16);
            break;
        case UINT_32_DATA:
            printf("%s: %u", message, alpha_res.data.alpha_uint32);
            break;
        case STRING_DATA:
            printf("%s:\n%s", message, alpha_res.data.string);
            break;
        case EMPTY_DATA:
            printf("done\n");
            break;
        default:
            printf("%s", message);
            break;
    }
    printf("\n");
}
