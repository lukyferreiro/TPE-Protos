#include "args.h"
#include "alpha.h"
#include "logger.h"
#include "netutils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
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
#define MAX_COMMANDS 14
void help();
static bool header_builder_with_param(struct alpha_req *alpha_req, unsigned cmd, char* param);
static bool header_builder_no_param(struct alpha_req *alpha_req, unsigned cmd);
void response_handler(struct alpha_req alpha_req,
                      struct alpha_res alpha_res, char *message);

/* comandos para implementacion tipo shell */
typedef struct alpha_shell_command {
    char *name;
    char *param_name;
    char *description;
    char *on_success_message;
    size_t nparams;
} alpha_shell_command;

//Arreglo de comandos disponibles con nparams que acepta, descripción y como llamar esos params
//Tal vez agregar el enum asociado a estos
alpha_shell_command alpha_shell_commands[] = {
    {.name = "list",
     .param_name = "<page_number>",
     .nparams = 1,
     .description = "Returns the specified page of the list of users "
                    "registered on the server",
     .on_success_message = "Users"},
    {.name = "hist",
     .param_name = "",
     .nparams = 0,
     .description =
         "Returns the amount of historic connections over the server",
     .on_success_message = "Amount of historic connections"},
    {.name = "conc",
     .param_name = "",
     .nparams = 0,
     .description =
         "Returns the amount of concurrent connections over the server",
     .on_success_message = "Amount of concurrent connections"},
    {.name = "bytes",
     .param_name = "",
     .nparams = 0,
     .description = "Returns the amount of bytes transfered over the server",
     .on_success_message = "Amount of bytes transfered"},
    {.name = "checksniff",
     .param_name = "",
     .nparams = 0,
     .description =
         "Returns the status of the password disector over the server",
     .on_success_message = "POP3 credential sniffer status"},
    {.name = "checkauth",
     .param_name = "",
     .nparams = 0,
     .description = "Returns the status of authentication over the server",
     .on_success_message = "Authentication status"},
    {.name = "getpage",
     .param_name = "",
     .nparams = 0,
     .description = "Returns the amount of users per page (max 200)",
     .on_success_message = "Users per page"},
    {.name = "add",
     .param_name = "user:pass",
     .nparams = 1,
     .description = "Command to add a user",
     .on_success_message = "User added successfully"},
    {.name = "del",
     .param_name = "user",
     .nparams = 1,
     .description = "Command to delete a user",
     .on_success_message = "User deleted successfully"},
    {.name = "sniff-on",
     .param_name = "",
     .nparams = 0,
     .description = "Command to enable POP3 credential sniffer over the server",
     .on_success_message = "POP3 credential sniffer enabled!"},
    {.name = "sniff-off",
     .param_name = "",
     .nparams = 0,
     .description = "Command to disable POP3 credential sniffer over the server",
     .on_success_message = "POP3 credential sniffer disabled!"},
    {.name = "auth-on",
     .param_name = "",
     .nparams = 0,
     .description = "Command to enable authentication over the server",
     .on_success_message = "Authentication enabled!"},
    {.name = "auth-off",
     .param_name = "",
     .nparams = 0,
     .description = "Command to disable authentication over the server",
     .on_success_message = "Authentication disabled!"},
    {.name = "setpage",
     .param_name = "<page_size>",
     .nparams = 1,
     .description = "Command to set page size (between 1 and 200)",
     .on_success_message = "Page size set successfully"},
};

static bool done = false;
static struct alpha_req alpha_req;
static struct alpha_res alpha_res;
uint16_t id_counter;
uint32_t token;

//shell que recibe los comandos 
int main(int argc, const char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: ./alpha_manager <alpha_manager_server_addr> <alpha_manager_server_port>\n");
        exit(EXIT_FAILURE);
    }

    char *token_env = getenv("ALPHA_TOKEN");
    if (token_env == NULL || strlen(token_env) != 4) {
        fprintf(stderr, "Alpha client: ERROR, erroneous or unexistent ALPHA_TOKEN "
                        "env variable.\n");
        fprintf(stderr,
                "The token name must be ALPHA_TOKEN and its value 4 bytes\n");
        exit(EXIT_FAILURE);
    }
    //convierto el token a int 
    token = strtoul(token_env, NULL, 10);

    //Configuración general a donde se envía la información
    int sockfd, valid_param, port, ip_type = ADDR_IPV4, i_command;
    //direcciones n ipv4 e ipv6
    struct sockaddr_in serv_addr;
    struct sockaddr_in6 serv_addr6;
    //buffers entrada salida, más buffer para la terminal del usuario
    char buffer_in[BUFFER_SIZE], buffer_out[BUFFER_SIZE], user_input[USER_INPUT_SIZE], *command, *param;
    memset(&serv_addr, 0, sizeof(serv_addr));
    memset(&serv_addr6, 0, sizeof(serv_addr6));

    if ((port = htons(atoi(argv[2]))) <= 0) {
        fprintf(stderr, "Alpha client: ERROR. Invalid port\n");
        exit(EXIT_FAILURE);
    }

    //Inicializo el puerto según la dirección ip que me mandaron
    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr.s_addr) > 0) {
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = port;
        ip_type = ADDR_IPV4;
    } else if (inet_pton(AF_INET6, argv[1], &serv_addr6.sin6_addr) > 0) {
        serv_addr6.sin6_family = AF_INET6;
        serv_addr6.sin6_port = port;
        ip_type = ADDR_IPV6;
    }

    //creo socket según tipo de ip
    if ((sockfd = socket(ip_type == ADDR_IPV4 ? AF_INET : AF_INET6, SOCK_DGRAM,
                         0)) < 0) {
        fprintf(stderr, "Alpha client: ERROR. Unable to create socket\n");
        exit(EXIT_FAILURE);
    }

    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        fprintf(stderr,
                "Alpha client: ERROR. Failed manager client setsockopt\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    //loop principal de la
    while (!done) {
        command = param = NULL;
        printf("alpha manager client >> ");

        //mirar tp3 de so
        memset(user_input, 0, USER_INPUT_SIZE);
        fgets(user_input, USER_INPUT_SIZE, stdin);

        if (user_input[0] == 0) {
            printf("No command specified.\n");
            continue;
        }

        //parseo lo que envía el user
        user_input[strcspn(user_input, "\r\n")] = 0;
        command = user_input;
        param = strchr(user_input, ' ');
        if (param != NULL) {
            *param++ = 0;
        }

        //si es help, corro help y no ejecuto el resto
        if (strcmp(command, "help") == 0) {
            help();
            continue;
        }

        //si no era help, comparo con los otros comandos y veo si el comando es o no válido
        for (i_command = 0; i_command < MAX_COMMANDS; i_command++) {
            if (strcmp(command, alpha_shell_commands[i_command].name) == 0) {
                if(alpha_shell_commands[i_command].nparams==0){
                    if(param==NULL){
                        valid_param=header_builder_no_param(&alpha_req, i_command);
                    }else{
                        valid_param=false;
                    }
                }
                if(alpha_shell_commands[i_command].nparams>0 ){
                    if(param!=NULL){
                        header_builder_with_param(&alpha_req, i_command, param);
                    }
                    else {
                        valid_param=false;
                    }
                }
                break;
            }
        }
        //validaciones si no existia comando o si le faltaba un parámetro
        if (i_command == MAX_COMMANDS) {
            printf("Invalid command.\n");
            continue;
        }
        if (valid_param == false) {
            printf("Invalid parameter\n");
            printf("Command: %s\t Usage: %s %s\t description: %s\n",
                   alpha_shell_commands[i_command].name, alpha_shell_commands[i_command].name, alpha_shell_commands[i_command].param_name,
                   alpha_shell_commands[i_command].description);
            continue;
        }

        //si el comando era válido, procedo a realizar la request al server
        int req_size;
        ssize_t resp_size;
        socklen_t len;

        memset(buffer_in, 0, BUFFER_SIZE);
        memset(buffer_out, 0, BUFFER_SIZE);

        if (alpha_req_to_packet(buffer_out, &alpha_req, &req_size) < 0) {
            fprintf(stderr, "Error building request packet");
        }

        
        if (ip_type == ADDR_IPV4) {
            //envio request al server
            sendto(sockfd, buffer_out, req_size, MSG_CONFIRM,
                   (const struct sockaddr *)&serv_addr, sizeof(serv_addr));

            //recibo respuesta
            resp_size =
                recvfrom(sockfd, (char *)buffer_in, BUFFER_SIZE, MSG_WAITALL,
                         (struct sockaddr *)&serv_addr, &len);
        } else {
            sendto(sockfd, buffer_out, req_size, MSG_CONFIRM,
                   (const struct sockaddr *)&serv_addr6, sizeof(serv_addr6));

            resp_size =
                recvfrom(sockfd, (char *)buffer_in, BUFFER_SIZE, MSG_WAITALL,
                         (struct sockaddr *)&serv_addr6, &len);
        }

        // Timeout
        if (resp_size < 0) {
            printf("Destination unreachable.\n");
            continue;
        }

        //handleo la response del server
        if (udp_to_alpha_res(buffer_in, &alpha_res) < 0) {
            fprintf(stderr, "Error converting raw packet to response");
            continue;
        }

        response_handler(alpha_req, alpha_res,
                         alpha_shell_commands[i_command].on_success_message);
    }
}

void help() { return; }

static bool header_builder_no_param(struct alpha_req *alpha_req, unsigned cmd) {
    alpha_req->alpha_version = ALPHA_V1;
    alpha_req->command = cmd;
    alpha_req->req_id = id_counter++;
    alpha_req->token = token;
    return true;
}

static bool header_builder_with_param(struct alpha_req *alpha_req, unsigned cmd, char* param) {
    switch (cmd)
    {
    case GET_LIST:
        int size = atoi(param);
        if (size <= 0)
            return false;
        alpha_req->data.alpha_uint8= size;
        break;
    
    case POST_ADD_USER:
        //Parametros tbd
        if (*param == USER_PASS_DELIMETER)
            return false;
        char *temp = strchr(param, USER_PASS_DELIMETER);
        if (temp == NULL || strlen(temp) > MAX_CRED_SIZE || *(temp++) == '\0' ||
            strlen(temp) > MAX_CRED_SIZE)
            return false;
        strcpy(alpha_req->data.string, param);
        break;    

    case POST_DEL_USER:
        if (param == NULL || strlen(param) > MAX_CRED_SIZE)
            return false;
        strcpy(alpha_req->data.string, param);
        break;

    case POST_USER_PAGE_SIZE:
        int arg = atoi(param);
        if (arg < MIN_PAGE_SIZE || arg > MAX_PAGE_SIZE) {
            return false;
        }
        alpha_req->data.alpha_uint8 = arg;
        break;
    default:
        return false;
        break;
    }

    return header_builder_no_param(alpha_req, cmd);
}
