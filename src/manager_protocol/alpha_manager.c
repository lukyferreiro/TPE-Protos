#include "alpha_manager.h"
#include "args.h"
#include "buffer.h"
#include "alpha.h"
#include "user_utils.h"
#include "logger.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define BUFFER_SIZE 4096
#define DEFAULT_PAGE_SIZE 200
#define N(x) (sizeof(x) / sizeof((x)[0]))
typedef void (*res_handler_fun)(alpha_res *, alpha_req);

static void set_response_header(struct alpha_req alpha_req,
                              struct alpha_res *alpha_res);

extern struct socks5_args socks5_args;

//done
static void get_list_handler(alpha_res* alpha_res, alpha_req alpha_req);
static void get_hist_conn_handler(alpha_res* alpha_res, alpha_req alpha_req);
static void get_conc_conn_handler(alpha_res* alpha_res, alpha_req alpha_req);
static void get_bytes_transf_handler(alpha_res* alpha_res, alpha_req alpha_req);
//done
static void get_is_sniff_handler(alpha_res* alpha_res, alpha_req alpha_req);
//done
static void get_is_auth_handler(alpha_res* alpha_res, alpha_req alpha_req);
//done 
static void get_user_page_size_handler(alpha_res* alpha_res, alpha_req alpha_req);
//done
static void post_add_user_handler(alpha_res* alpha_res, alpha_req alpha_req);
//done
static void post_del_user_handler(alpha_res* alpha_res, alpha_req alpha_req);
//done
static void post_enable_sniff_handler(alpha_res* alpha_res, alpha_req alpha_req);
//done
static void post_disable_sniff_handler(alpha_res* alpha_res, alpha_req alpha_req);
//done
static void post_enable_auth_handler(alpha_res* alpha_res, alpha_req alpha_req);
//done
static void post_disable_auth_handler(alpha_res* alpha_res, alpha_req alpha_req);
//done
static void post_user_page_size_handler(alpha_res* alpha_res, alpha_req alpha_req);


res_handler_fun function_handlers[] = {
    get_list_handler,        get_hist_conn_handler,
    get_conc_conn_handler,   get_bytes_transf_handler,
    get_is_sniff_handler, get_is_auth_handler,
    get_user_page_size_handler, post_add_user_handler,        
    post_del_user_handler, post_enable_sniff_handler, 
    post_disable_sniff_handler, post_enable_auth_handler,
    post_disable_auth_handler, post_user_page_size_handler
};

struct alpha_manager {
    struct alpha_req alpha_req;
    struct alpha_res alpha_res;

    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;

    int response_len;
    uint8_t page_size;

    char buffer_read[BUFFER_SIZE], buffer_write[BUFFER_SIZE];
};

struct alpha_manager alpha_manager;

void manager_receive(struct selector_key *key) {
    alpha_manager.client_addr_len = sizeof(alpha_manager.client_addr);
    alpha_manager.response_len = 0;
    alpha_manager.page_size =
    alpha_manager.page_size == 0 ? DEFAULT_PAGE_SIZE : alpha_manager.page_size;
    memset(alpha_manager.buffer_read, 0, BUFFER_SIZE);
    memset(alpha_manager.buffer_write, 0, BUFFER_SIZE);
    memset(&alpha_manager.alpha_req, 0, sizeof(alpha_req));
    memset(&alpha_manager.alpha_res, 0, sizeof(alpha_res));
    memset(&alpha_manager.client_addr, 0, sizeof(struct sockaddr_storage));

    ssize_t n = recvfrom(key->fd, alpha_manager.buffer_read, BUFFER_SIZE, 0,
                         (struct sockaddr *)&alpha_manager.client_addr,
                         &alpha_manager.client_addr_len);

    if (n <= 0) {
        log(LOG_ERROR, "Alpha manager: recvfrom failed: %s ",
                  strerror(errno));
    }

    if (udp_to_alpha_req(alpha_manager.buffer_read,
                                  &alpha_manager.alpha_req) < 0) {
        log(LOG_ERROR,
                  "Alpha manager: converting raw packet to request failed");
    }

    set_response_header(alpha_manager.alpha_req, &alpha_manager.alpha_res);

    if (alpha_manager.alpha_res.status == SC_OK) {
     //arreglo de punteros a función que guardaran el resultado debidamente en response para cada comando
        function_handlers[alpha_manager.alpha_req.command](&alpha_manager.alpha_res, alpha_manager.alpha_req);
    }

    if (alpha_res_to_packet(alpha_manager.buffer_write,
                               &alpha_manager.alpha_res,
                               &alpha_manager.response_len) < 0) {
        log(LOG_ERROR,
                  "Alpha manager: converting response to buffer failed");
    }

    if (sendto(key->fd, alpha_manager.buffer_write, alpha_manager.response_len, 0,
               (const struct sockaddr *)&alpha_manager.client_addr,
               alpha_manager.client_addr_len) < 0) {
        log(LOG_ERROR, "Alpha manager: sendto client not available");
    }
}

static bool check_admin_token(struct alpha_req alpha_req) {
 //   if (alpha_req.token != socks5_args.manager_token)
   //     return false;
    //return true;
    //Agregar campo a socks5_args
    return true;
}

static bool check_version(struct alpha_req alpha_req) {
    if (alpha_req.alpha_version != ALPHA_V1)
        return false;
    return true;
}
static bool check_cmd(struct alpha_req alpha_req) {
    if (alpha_req.command >= COMMANDS_SIZE){
        return false;
    }
    return true;
}

//chequeo argumentos según tipos de dato que se requieran
static bool check_arguments(struct alpha_req alpha_req) {
    bool ret = true;
    switch (cmd_to_req_data_type(alpha_req.command)) {
    case UINT_8_DATA:
        //ret = check_alter_uint8(alpha_req);
        break;
    case STRING_DATA:
        //ret = check_alter_string(alpha_req);
    default:
        break;
    }
    return ret;
}

static void set_response_header(struct alpha_req alpha_req,
                              struct alpha_res *alpha_res) {
    alpha_res->status = SC_OK;
    if (check_version(alpha_req) == false) {
        alpha_res->status = SC_INVALID_VERSION;
    } else if (check_admin_token(alpha_req) == false) {
        alpha_res->status = SC_BAD_CREDENTIALS;
    } else if (check_cmd(alpha_req) == false) {
        alpha_res->status = SC_INVALID_COMMAND;
    } else if (check_arguments(alpha_req) == false) {
        alpha_res->status = SC_INVALID_ARGUMENT;
    }

    alpha_res->alpha_version = alpha_req.alpha_version;
    alpha_res->res_id = alpha_req.req_id;
    alpha_res->command = alpha_req.command;
}

static void get_list_handler(alpha_res* alpha_res, alpha_req alpha_req){
    int offset = (alpha_req.data.alpha_uint8 - 1) * alpha_manager.page_size;
    if (offset > socks5_args.nusers) {
        alpha_res->data.string[0] = 0;
        return;
    }
    int aux_offset = offset;
    int string_offset = 0;

    //Salteo los campos que pueden llegar a estar vacíos
    //cuando elimino usuarios no dejo todos juntos en el array
    for (int i = 0; i < aux_offset; i++) {
        if (socks5_args.users[i].name[0] == '\0')
            offset++;
    }
    for (int i = offset, j = 0; i < MAX_USERS && j < alpha_manager.page_size;
         i++) {
        if (socks5_args.users[i].name[0] != '\0') {
            strcpy(alpha_res->data.string + string_offset, socks5_args.users[i].name);
            string_offset += strlen(socks5_args.users[i].name);
            *(alpha_res->data.string + string_offset++) = '\n';
            j++;
        }
    }
    *(alpha_res->data.string + --string_offset) = '\0';
}

static void get_hist_conn_handler(alpha_res* alpha_res, alpha_req alpha_req){

} 

static void get_conc_conn_handler(alpha_res* alpha_res, alpha_req alpha_req){

} 

static void get_bytes_transf_handler(alpha_res* alpha_res, alpha_req alpha_req){

}

static void get_is_sniff_handler(alpha_res* alpha_res, alpha_req alpha_req){
    alpha_res->data.alpha_uint8=socks5_args.sniffing;
}

static void get_is_auth_handler(alpha_res* alpha_res, alpha_req alpha_req){
    alpha_res->data.alpha_uint8=socks5_args.auth;
}

static void get_user_page_size_handler(alpha_res* alpha_res, alpha_req alpha_req){
    alpha_res->data.alpha_uint8=alpha_manager.page_size;
}

static void post_add_user_handler(alpha_res* alpha_res, alpha_req alpha_req){
    char *username = alpha_req.data.string;
    char *password;
    password = strchr(username, USER_PASSWORD_DELIMETER);
    *password++ = 0;//agrego el 0 final a la password
    if (!server_is_full()) {
        if (!user_is_registered(username)) {
            add_user(username, password);
            alpha_res->status = SC_OK;
        } else {
            alpha_res->status = SC_INVALID_USER_IS_REGISTERED;
        }
    } else {
        alpha_res->status = SC_SERVER_IS_FULL;
    }
}

static void post_del_user_handler(alpha_res* alpha_res, alpha_req alpha_req){
    char *username = alpha_req.data.string;
    if (user_is_registered(username)) {
        delete_user(username);
        alpha_res->status = SC_OK;
    } else {
        alpha_res->status = SC_USER_NOT_FOUND;
    }
}

static void post_enable_sniff_handler(alpha_res* alpha_res, alpha_req alpha_req){
    socks5_args.sniffing = true;
}

static void post_disable_sniff_handler(alpha_res* alpha_res, alpha_req alpha_req){
    socks5_args.sniffing = false;
}

static void post_enable_auth_handler(alpha_res* alpha_res, alpha_req alpha_req){
    socks5_args.auth = true;
}

static void post_disable_auth_handler(alpha_res* alpha_res, alpha_req alpha_req){
    socks5_args.auth = false;
}

static void post_user_page_size_handler(alpha_res* alpha_res, alpha_req alpha_req){
    alpha_manager.page_size = alpha_req.data.alpha_uint8;
}