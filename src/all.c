/**
 * Shared Object Rewrite Stub
 */

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "func-list.h"

#define FUNC_COUNT (sizeof((func_list)) / sizeof((func_list)[0]))

void* func_addr[FUNC_COUNT];

static void setup() __attribute__ ((constructor));
static void cleanup() __attribute__ ((destructor));

/**
 * Original shared object handle
 */
static void* libSSL = NULL;

/**
 * Load function address list
 */
static void setup() {
    size_t i;
    if (libSSL)
    {
        return;
    }
    // printf("# loading libSSL.so library...\n");
    libSSL = dlopen("libSSL.so", RTLD_NOW);
    if (!libSSL) {
        // fprintf(stderr, "# unable to open libSSL.so: %i\n", errno);
        exit(1);
    }
    // printf("# done loading libSSL.so\n");
    // printf("# resolving %i symbols...\n", FUNC_COUNT);    
    for (i = 0; i < FUNC_COUNT; i++) {
        if (!(func_addr[i] = dlsym(libSSL, func_list[i])))
        {
            // fprintf(stderr, "# symbol not found: %s\n", func_list[i]);
            exit(1);
        }
    }
    // printf("# resolved all symbols.\n");
}

/**
 * Unload function address list
 */
static void cleanup() {
    if (libSSL)
    {
        // printf("# unloading libSSL.so library...\n");
        dlclose(libSSL);
        // printf("# done unloading libSSL.so\n");
        libSSL = NULL;
    }
}

/*
void* SSL_write(void* a, void* b, void* c) {
    void* x = ((void* (*) (void*, void*, void*)) func_addr[8])(a, b, c);
    int fd = ((int (*) (void*)) func_addr[146])(a);
    if ((int) x > 0) {
        log_binary('W', fd, b, (int) x);
    }
    return x;
}


void* SSL_read(void* a, void* b, void* c) {
    void* x = ((void* (*) (void*, void*, void*)) func_addr[5])(a, b, c);
    int fd = ((int (*) (void*)) func_addr[146])(a);
    if ((int) x > 0) {
        log_binary('R', fd, b, (int) x);
    }
    return x;
}
*/
/**
 * Push to log utility
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define LOG_FILE_PATH "/data/data/package_of_your_app/files/log"

/**
 * Log entity header
 */
struct log_entity_header_t
{
    uint8_t magic[3];
    uint8_t opcode;
    uint32_t fd;
    uint32_t sec;
    uint32_t nsec;
    uint32_t len;
}  __attribute__ ( ( packed ) );

/**
 * Log entity
 */
struct log_entity_t
{
    struct log_entity_header_t header;
    unsigned char body[65536];
}  __attribute__ ( ( packed ) );

/**
 * Log binary data to file
 */
static void log_binary(char opcode, int sockfd, const void* buf, int len)
{
    int logfd;
    pid_t pid;
    size_t total;
    char path[256];
    struct timespec ts = { 0 };
    struct log_entity_t entity;

    /* Check buffer bounds */
    if (len > sizeof(entity.body))
    {
        len = sizeof(entity.body);
    }
    
    /* Gather log entity info */
    pid = getpid();
    clock_gettime(CLOCK_MONOTONIC, &ts);

    /* Setup log entity header */
    entity.header.magic[0] = 'L';
    entity.header.magic[1] = 'o';
    entity.header.magic[2] = 'g';
    entity.header.opcode = opcode;
    entity.header.fd = htonl(sockfd);
    entity.header.sec = htonl(ts.tv_sec);
    entity.header.nsec = htonl(ts.tv_nsec);
    entity.header.len = htonl(len);
    
    /* Put log entity body */
    memcpy(entity.body, buf, len);

    /* Save log entity to file */
    if((logfd = open(LOG_FILE_PATH, O_CREAT | O_APPEND | O_WRONLY, 0666)) >= 0)
    {
        write(logfd, &entity, sizeof(entity.header) + len);
        close(logfd);
    }
}

/**
 * Log string to file
 */
static void log_string(char opcode, int sockfd, const char* string)
{
    log_binary(opcode, sockfd, string, strlen(string));
}
void* SSL_set_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[0])(a, b, c, d);
}
void* __aeabi_unwind_cpp_pr1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[1])(a, b, c, d);
}
void* SSL_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[2])(a, b, c, d);
}
void* SSL_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[3])(a, b, c, d);
}
void* __aeabi_unwind_cpp_pr0(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[4])(a, b, c, d);
}
void* SSL_get_error(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[6])(a, b, c, d);
}
void* SSL_renegotiate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[7])(a, b, c, d);
}


void* SSL_write(void* a, void* b, void* c) {
    void* x = ((void* (*) (void*, void*, void*)) func_addr[8])(a, b, c);
    int fd = ((int (*) (void*)) func_addr[146])(a);
    if ((int) x > 0) {
        log_binary('W', fd, b, (int) x);
    }
    return x;
}


void* SSL_read(void* a, void* b, void* c) {
    void* x = ((void* (*) (void*, void*, void*)) func_addr[5])(a, b, c);
    int fd = ((int (*) (void*)) func_addr[146])(a);
    if ((int) x > 0) {
        log_binary('R', fd, b, (int) x);
    }
    return x;
}

void* SSL_set_connect_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[9])(a, b, c, d);
}
void* SSL_set_accept_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[10])(a, b, c, d);
}
void* SSL_clear(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[11])(a, b, c, d);
}
void* SSL_get_rbio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[12])(a, b, c, d);
}
void* SSL_pending(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[13])(a, b, c, d);
}
void* SSL_set_bio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[14])(a, b, c, d);
}
void* SSL_do_handshake(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[15])(a, b, c, d);
}
void* SSL_get_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[16])(a, b, c, d);
}
void* BIO_f_ssl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[17])(a, b, c, d);
}
void* BIO_new_ssl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[18])(a, b, c, d);
}
void* SSL_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[19])(a, b, c, d);
}
void* BIO_new_ssl_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[20])(a, b, c, d);
}
void* BIO_new_buffer_ssl_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[21])(a, b, c, d);
}
void* BIO_ssl_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[22])(a, b, c, d);
}
void* SSL_get_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[23])(a, b, c, d);
}
void* SSL_get_wbio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[24])(a, b, c, d);
}
void* SSL_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[25])(a, b, c, d);
}
void* DTLSv1_handle_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[26])(a, b, c, d);
}
void* pqueue_iterator(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[27])(a, b, c, d);
}
void* pqueue_next(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[28])(a, b, c, d);
}
void* pitem_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[29])(a, b, c, d);
}
void* pqueue_insert(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[30])(a, b, c, d);
}
void* pqueue_pop(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[31])(a, b, c, d);
}
void* pitem_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[32])(a, b, c, d);
}
void* pqueue_find(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[33])(a, b, c, d);
}
void* pqueue_peek(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[34])(a, b, c, d);
}
void* pqueue_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[35])(a, b, c, d);
}
void* pqueue_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[36])(a, b, c, d);
}
void* DTLSv1_get_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[37])(a, b, c, d);
}
void* DTLS_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[38])(a, b, c, d);
}
void* DTLSv1_2_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[39])(a, b, c, d);
}
void* DTLSv1_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[40])(a, b, c, d);
}
void* DTLSv1_2_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[41])(a, b, c, d);
}
void* DTLSv1_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[42])(a, b, c, d);
}
void* DTLSv1_2_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[43])(a, b, c, d);
}
void* DTLSv1_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[44])(a, b, c, d);
}
void* DTLS_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[45])(a, b, c, d);
}
void* DTLS_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[46])(a, b, c, d);
}
void* SSL_CTX_remove_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[47])(a, b, c, d);
}
void* SSL_CTX_set_srtp_profiles(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[48])(a, b, c, d);
}
void* SSL_set_srtp_profiles(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[49])(a, b, c, d);
}
void* SSL_get_srtp_profiles(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[50])(a, b, c, d);
}
void* SSL_get_selected_srtp_profile(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[51])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_use_srtp(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[52])(a, b, c, d);
}
void* SSL_set_tlsext_use_srtp(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[53])(a, b, c, d);
}
void* pqueue_size(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[54])(a, b, c, d);
}
void* SSL_set_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[55])(a, b, c, d);
}
void* SSL_get_ciphers(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[56])(a, b, c, d);
}
void* SSL_get_cipher_by_value(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[57])(a, b, c, d);
}
void* SSL_use_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[58])(a, b, c, d);
}
void* SSL_use_PrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[59])(a, b, c, d);
}
void* SSL_get_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[60])(a, b, c, d);
}
void* SSL_session_reused(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[61])(a, b, c, d);
}
void* SSL_total_renegotiations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[62])(a, b, c, d);
}
void* SSL_num_renegotiations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[63])(a, b, c, d);
}
void* SSL_CTX_need_tmp_RSA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[64])(a, b, c, d);
}
void* SSL_CTX_set_tmp_rsa(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[65])(a, b, c, d);
}
void* SSL_set_tmp_rsa(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[66])(a, b, c, d);
}
void* SSL_CTX_set_tmp_dh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[67])(a, b, c, d);
}
void* SSL_set_tmp_dh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[68])(a, b, c, d);
}
void* SSL_CTX_set_tmp_ecdh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[69])(a, b, c, d);
}
void* SSL_set_tmp_ecdh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[70])(a, b, c, d);
}
void* SSL_CTX_enable_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[71])(a, b, c, d);
}
void* SSL_enable_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[72])(a, b, c, d);
}
void* SSL_CTX_set1_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[73])(a, b, c, d);
}
void* SSL_set1_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[74])(a, b, c, d);
}
void* SSL_get_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[75])(a, b, c, d);
}
void* SSL_set_tlsext_host_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[76])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_servername_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[77])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_servername_arg(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[78])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_ticket_key_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[79])(a, b, c, d);
}
void* TLS_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[80])(a, b, c, d);
}
void* SSLv23_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[81])(a, b, c, d);
}
void* TLSv1_2_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[82])(a, b, c, d);
}
void* TLSv1_1_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[83])(a, b, c, d);
}
void* TLSv1_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[84])(a, b, c, d);
}
void* SSLv3_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[85])(a, b, c, d);
}
void* TLSv1_2_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[86])(a, b, c, d);
}
void* TLSv1_1_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[87])(a, b, c, d);
}
void* TLSv1_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[88])(a, b, c, d);
}
void* SSLv3_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[89])(a, b, c, d);
}
void* TLSv1_2_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[90])(a, b, c, d);
}
void* TLSv1_1_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[91])(a, b, c, d);
}
void* TLSv1_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[92])(a, b, c, d);
}
void* SSLv3_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[93])(a, b, c, d);
}
void* SSLv23_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[94])(a, b, c, d);
}
void* SSLv23_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[95])(a, b, c, d);
}
void* SSL_in_false_start(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[96])(a, b, c, d);
}
void* SSL_early_callback_ctx_extension_get(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[97])(a, b, c, d);
}
void* SSL_get_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[98])(a, b, c, d);
}
void* SSL_SESSION_to_bytes_for_ticket(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[99])(a, b, c, d);
}
void* SSL_library_init(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[100])(a, b, c, d);
}
void* SSL_load_error_strings(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[101])(a, b, c, d);
}
void* SSL_SESSION_to_bytes(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[102])(a, b, c, d);
}
void* i2d_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[103])(a, b, c, d);
}
void* d2i_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[104])(a, b, c, d);
}
void* SSL_SESSION_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[105])(a, b, c, d);
}
void* SSL_SESSION_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[106])(a, b, c, d);
}
void* SSL_get_ex_data_X509_STORE_CTX_idx(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[107])(a, b, c, d);
}
void* SSL_dup_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[108])(a, b, c, d);
}
void* SSL_set_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[109])(a, b, c, d);
}
void* SSL_CTX_set_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[110])(a, b, c, d);
}
void* SSL_CTX_get_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[111])(a, b, c, d);
}
void* SSL_add_client_CA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[112])(a, b, c, d);
}
void* SSL_CTX_add_client_CA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[113])(a, b, c, d);
}
void* SSL_load_client_CA_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[114])(a, b, c, d);
}
void* SSL_add_file_cert_subjects_to_stack(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[115])(a, b, c, d);
}
void* SSL_add_dir_cert_subjects_to_stack(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[116])(a, b, c, d);
}
void* SSL_CIPHER_get_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[117])(a, b, c, d);
}
void* SSL_CIPHER_is_AES(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[118])(a, b, c, d);
}
void* SSL_CIPHER_has_MD5_HMAC(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[119])(a, b, c, d);
}
void* SSL_CIPHER_is_AESGCM(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[120])(a, b, c, d);
}
void* SSL_CIPHER_is_CHACHA20POLY1305(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[121])(a, b, c, d);
}
void* SSL_CIPHER_get_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[122])(a, b, c, d);
}
void* SSL_CIPHER_get_kx_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[123])(a, b, c, d);
}
void* SSL_CIPHER_get_rfc_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[124])(a, b, c, d);
}
void* SSL_CIPHER_get_bits(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[125])(a, b, c, d);
}
void* SSL_CIPHER_description(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[126])(a, b, c, d);
}
void* SSL_CIPHER_get_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[127])(a, b, c, d);
}
void* SSL_COMP_get_compression_methods(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[128])(a, b, c, d);
}
void* SSL_COMP_add_compression_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[129])(a, b, c, d);
}
void* SSL_COMP_get_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[130])(a, b, c, d);
}
void* SSL_CTX_set_session_id_context(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[131])(a, b, c, d);
}
void* SSL_set_session_id_context(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[132])(a, b, c, d);
}
void* SSL_CTX_set_generate_session_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[133])(a, b, c, d);
}
void* SSL_set_generate_session_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[134])(a, b, c, d);
}
void* SSL_has_matching_session_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[135])(a, b, c, d);
}
void* SSL_CTX_set_purpose(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[136])(a, b, c, d);
}
void* SSL_set_purpose(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[137])(a, b, c, d);
}
void* SSL_CTX_set_trust(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[138])(a, b, c, d);
}
void* SSL_set_trust(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[139])(a, b, c, d);
}
void* SSL_CTX_set1_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[140])(a, b, c, d);
}
void* SSL_set1_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[141])(a, b, c, d);
}
void* SSL_CTX_get0_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[142])(a, b, c, d);
}
void* SSL_get0_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[143])(a, b, c, d);
}
void* SSL_certs_clear(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[144])(a, b, c, d);
}
void* SSL_get_rfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[145])(a, b, c, d);
}
void* SSL_get_fd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[146])(a, b, c, d);
}
void* SSL_get_wfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[147])(a, b, c, d);
}
void* SSL_set_fd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[148])(a, b, c, d);
}
void* SSL_set_wfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[149])(a, b, c, d);
}
void* SSL_set_rfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[150])(a, b, c, d);
}
void* SSL_get_finished(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[151])(a, b, c, d);
}
void* SSL_get_peer_finished(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[152])(a, b, c, d);
}
void* SSL_get_verify_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[153])(a, b, c, d);
}
void* SSL_get_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[154])(a, b, c, d);
}
void* SSL_get_verify_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[155])(a, b, c, d);
}
void* SSL_CTX_get_verify_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[156])(a, b, c, d);
}
void* SSL_CTX_get_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[157])(a, b, c, d);
}
void* SSL_CTX_get_verify_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[158])(a, b, c, d);
}
void* SSL_set_verify(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[159])(a, b, c, d);
}
void* SSL_set_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[160])(a, b, c, d);
}
void* SSL_CTX_get_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[161])(a, b, c, d);
}
void* SSL_get_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[162])(a, b, c, d);
}
void* SSL_CTX_set_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[163])(a, b, c, d);
}
void* SSL_set_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[164])(a, b, c, d);
}
void* SSL_get_peer_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[165])(a, b, c, d);
}
void* SSL_get_peer_cert_chain(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[166])(a, b, c, d);
}
void* SSL_CTX_check_private_key(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[167])(a, b, c, d);
}
void* SSL_check_private_key(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[168])(a, b, c, d);
}
void* SSL_get_default_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[169])(a, b, c, d);
}
void* SSL_peek(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[170])(a, b, c, d);
}
void* SSL_CTX_set_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[171])(a, b, c, d);
}
void* SSL_set_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[172])(a, b, c, d);
}
void* SSL_CTX_clear_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[173])(a, b, c, d);
}
void* SSL_clear_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[174])(a, b, c, d);
}
void* SSL_CTX_get_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[175])(a, b, c, d);
}
void* SSL_CTX_set_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[176])(a, b, c, d);
}
void* SSL_set_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[177])(a, b, c, d);
}
void* SSL_CTX_clear_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[178])(a, b, c, d);
}
void* SSL_clear_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[179])(a, b, c, d);
}
void* SSL_CTX_get_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[180])(a, b, c, d);
}
void* SSL_CTX_get_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[181])(a, b, c, d);
}
void* SSL_CTX_set_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[182])(a, b, c, d);
}
void* SSL_get_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[183])(a, b, c, d);
}
void* SSL_set_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[184])(a, b, c, d);
}
void* SSL_CTX_set_max_send_fragment(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[185])(a, b, c, d);
}
void* SSL_set_max_send_fragment(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[186])(a, b, c, d);
}
void* SSL_set_mtu(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[187])(a, b, c, d);
}
void* SSL_get_secure_renegotiation_support(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[188])(a, b, c, d);
}
void* SSL_ctrl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[189])(a, b, c, d);
}
void* SSL_CTX_sessions(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[190])(a, b, c, d);
}
void* SSL_CTX_sess_number(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[191])(a, b, c, d);
}
void* SSL_CTX_sess_set_cache_size(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[192])(a, b, c, d);
}
void* SSL_CTX_sess_get_cache_size(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[193])(a, b, c, d);
}
void* SSL_CTX_set_session_cache_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[194])(a, b, c, d);
}
void* SSL_CTX_get_session_cache_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[195])(a, b, c, d);
}
void* SSL_CTX_ctrl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[196])(a, b, c, d);
}
void* SSL_get_cipher_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[197])(a, b, c, d);
}
void* SSL_CTX_set_cipher_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[198])(a, b, c, d);
}
void* SSL_CTX_set_cipher_list_tls11(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[199])(a, b, c, d);
}
void* SSL_set_cipher_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[200])(a, b, c, d);
}
void* SSL_get_servername(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[201])(a, b, c, d);
}
void* SSL_get_servername_type(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[202])(a, b, c, d);
}
void* SSL_CTX_enable_signed_cert_timestamps(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[203])(a, b, c, d);
}
void* SSL_enable_signed_cert_timestamps(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[204])(a, b, c, d);
}
void* SSL_CTX_enable_ocsp_stapling(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[205])(a, b, c, d);
}
void* SSL_enable_ocsp_stapling(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[206])(a, b, c, d);
}
void* SSL_get0_signed_cert_timestamp_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[207])(a, b, c, d);
}
void* SSL_get0_ocsp_response(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[208])(a, b, c, d);
}
void* SSL_select_next_proto(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[209])(a, b, c, d);
}
void* SSL_get0_next_proto_negotiated(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[210])(a, b, c, d);
}
void* SSL_CTX_set_next_protos_advertised_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[211])(a, b, c, d);
}
void* SSL_CTX_set_next_proto_select_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[212])(a, b, c, d);
}
void* SSL_CTX_set_alpn_protos(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[213])(a, b, c, d);
}
void* SSL_set_alpn_protos(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[214])(a, b, c, d);
}
void* SSL_CTX_set_alpn_select_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[215])(a, b, c, d);
}
void* SSL_get0_alpn_selected(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[216])(a, b, c, d);
}
void* SSL_export_keying_material(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[217])(a, b, c, d);
}
void* SSL_CTX_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[218])(a, b, c, d);
}
void* SSL_CTX_flush_sessions(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[219])(a, b, c, d);
}
void* SSL_CTX_set_default_passwd_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[220])(a, b, c, d);
}
void* SSL_CTX_set_default_passwd_cb_userdata(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[221])(a, b, c, d);
}
void* SSL_CTX_set_cert_verify_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[222])(a, b, c, d);
}
void* SSL_CTX_set_verify(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[223])(a, b, c, d);
}
void* SSL_CTX_set_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[224])(a, b, c, d);
}
void* SSL_CTX_set_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[225])(a, b, c, d);
}
void* SSL_set_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[226])(a, b, c, d);
}
void* SSL_CTX_add_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[227])(a, b, c, d);
}
void* SSL_SESSION_up_ref(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[228])(a, b, c, d);
}
void* SSL_set_ssl_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[229])(a, b, c, d);
}
void* SSL_get_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[230])(a, b, c, d);
}
void* SSL_SESSION_get_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[231])(a, b, c, d);
}
void* SSL_accept(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[232])(a, b, c, d);
}
void* SSL_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[233])(a, b, c, d);
}
void* SSL_get_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[234])(a, b, c, d);
}
void* SSL_get_privatekey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[235])(a, b, c, d);
}
void* SSL_CTX_get0_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[236])(a, b, c, d);
}
void* SSL_CTX_get0_privatekey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[237])(a, b, c, d);
}
void* SSL_get_current_cipher(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[238])(a, b, c, d);
}
void* SSL_get_current_compression(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[239])(a, b, c, d);
}
void* SSL_get_current_expansion(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[240])(a, b, c, d);
}
void* SSL_CTX_set_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[241])(a, b, c, d);
}
void* SSL_CTX_get_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[242])(a, b, c, d);
}
void* SSL_set_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[243])(a, b, c, d);
}
void* SSL_get_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[244])(a, b, c, d);
}
void* SSL_set_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[245])(a, b, c, d);
}
void* SSL_get_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[246])(a, b, c, d);
}
void* SSL_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[247])(a, b, c, d);
}
void* SSL_get_SSL_CTX(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[248])(a, b, c, d);
}
void* SSL_set_SSL_CTX(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[249])(a, b, c, d);
}
void* SSL_CTX_set_default_verify_paths(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[250])(a, b, c, d);
}
void* SSL_CTX_load_verify_locations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[251])(a, b, c, d);
}
void* SSL_renegotiate_pending(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[252])(a, b, c, d);
}
void* SSL_set_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[253])(a, b, c, d);
}
void* SSL_set_verify_result(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[254])(a, b, c, d);
}
void* SSL_get_verify_result(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[255])(a, b, c, d);
}
void* SSL_get_ex_new_index(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[256])(a, b, c, d);
}
void* SSL_set_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[257])(a, b, c, d);
}
void* SSL_get_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[258])(a, b, c, d);
}
void* SSL_CTX_get_ex_new_index(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[259])(a, b, c, d);
}
void* SSL_CTX_set_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[260])(a, b, c, d);
}
void* SSL_CTX_get_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[261])(a, b, c, d);
}
void* SSL_CTX_get_cert_store(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[262])(a, b, c, d);
}
void* SSL_CTX_set_cert_store(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[263])(a, b, c, d);
}
void* SSL_want(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[264])(a, b, c, d);
}
void* SSL_CTX_set_tmp_rsa_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[265])(a, b, c, d);
}
void* SSL_set_tmp_rsa_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[266])(a, b, c, d);
}
void* SSL_CTX_set_tmp_dh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[267])(a, b, c, d);
}
void* SSL_set_tmp_dh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[268])(a, b, c, d);
}
void* SSL_CTX_set_tmp_ecdh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[269])(a, b, c, d);
}
void* SSL_set_tmp_ecdh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[270])(a, b, c, d);
}
void* SSL_CTX_use_psk_identity_hint(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[271])(a, b, c, d);
}
void* SSL_use_psk_identity_hint(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[272])(a, b, c, d);
}
void* SSL_get_psk_identity_hint(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[273])(a, b, c, d);
}
void* SSL_get_psk_identity(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[274])(a, b, c, d);
}
void* SSL_set_psk_client_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[275])(a, b, c, d);
}
void* SSL_CTX_set_psk_client_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[276])(a, b, c, d);
}
void* SSL_set_psk_server_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[277])(a, b, c, d);
}
void* SSL_CTX_set_psk_server_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[278])(a, b, c, d);
}
void* SSL_CTX_set_min_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[279])(a, b, c, d);
}
void* SSL_CTX_set_max_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[280])(a, b, c, d);
}
void* SSL_CTX_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[281])(a, b, c, d);
}
void* SSL_set_min_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[282])(a, b, c, d);
}
void* SSL_set_max_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[283])(a, b, c, d);
}
void* SSL_CTX_set_msg_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[284])(a, b, c, d);
}
void* SSL_CTX_set_msg_callback_arg(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[285])(a, b, c, d);
}
void* SSL_set_msg_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[286])(a, b, c, d);
}
void* SSL_set_msg_callback_arg(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[287])(a, b, c, d);
}
void* SSL_CTX_set_keylog_bio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[288])(a, b, c, d);
}
void* SSL_cutthrough_complete(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[289])(a, b, c, d);
}
void* SSL_get_structure_sizes(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[290])(a, b, c, d);
}
void* SSL_cache_hit(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[291])(a, b, c, d);
}
void* SSL_is_server(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[292])(a, b, c, d);
}
void* SSL_CTX_set_dos_protection_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[293])(a, b, c, d);
}
void* SSL_enable_fastradio_padding(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[294])(a, b, c, d);
}
void* SSL_set_reject_peer_renegotiations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[295])(a, b, c, d);
}
void* SSL_get_rc4_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[296])(a, b, c, d);
}
void* SSL_get_tls_unique(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[297])(a, b, c, d);
}
void* SSL_CTX_sess_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[298])(a, b, c, d);
}
void* SSL_CTX_sess_connect_good(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[299])(a, b, c, d);
}
void* SSL_CTX_sess_connect_renegotiate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[300])(a, b, c, d);
}
void* SSL_CTX_sess_accept(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[301])(a, b, c, d);
}
void* SSL_CTX_sess_accept_renegotiate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[302])(a, b, c, d);
}
void* SSL_CTX_sess_accept_good(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[303])(a, b, c, d);
}
void* SSL_CTX_sess_hits(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[304])(a, b, c, d);
}
void* SSL_CTX_sess_cb_hits(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[305])(a, b, c, d);
}
void* SSL_CTX_sess_misses(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[306])(a, b, c, d);
}
void* SSL_CTX_sess_timeouts(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[307])(a, b, c, d);
}
void* SSL_CTX_sess_cache_full(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[308])(a, b, c, d);
}
void* SSL_use_certificate_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[309])(a, b, c, d);
}
void* SSL_use_certificate_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[310])(a, b, c, d);
}
void* SSL_use_RSAPrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[311])(a, b, c, d);
}
void* SSL_use_RSAPrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[312])(a, b, c, d);
}
void* SSL_use_RSAPrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[313])(a, b, c, d);
}
void* SSL_use_PrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[314])(a, b, c, d);
}
void* SSL_use_PrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[315])(a, b, c, d);
}
void* SSL_CTX_use_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[316])(a, b, c, d);
}
void* SSL_CTX_use_certificate_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[317])(a, b, c, d);
}
void* SSL_CTX_use_certificate_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[318])(a, b, c, d);
}
void* SSL_CTX_use_RSAPrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[319])(a, b, c, d);
}
void* SSL_CTX_use_RSAPrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[320])(a, b, c, d);
}
void* SSL_CTX_use_RSAPrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[321])(a, b, c, d);
}
void* SSL_CTX_use_PrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[322])(a, b, c, d);
}
void* SSL_CTX_use_PrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[323])(a, b, c, d);
}
void* SSL_CTX_use_PrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[324])(a, b, c, d);
}
void* SSL_CTX_use_certificate_chain_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[325])(a, b, c, d);
}
void* SSL_magic_pending_session_ptr(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[326])(a, b, c, d);
}
void* SSL_get_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[327])(a, b, c, d);
}
void* SSL_SESSION_get_ex_new_index(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[328])(a, b, c, d);
}
void* SSL_SESSION_set_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[329])(a, b, c, d);
}
void* SSL_SESSION_get_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[330])(a, b, c, d);
}
void* SSL_SESSION_get_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[331])(a, b, c, d);
}
void* SSL_get1_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[332])(a, b, c, d);
}
void* SSL_SESSION_set_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[333])(a, b, c, d);
}
void* SSL_SESSION_get_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[334])(a, b, c, d);
}
void* SSL_SESSION_get_time(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[335])(a, b, c, d);
}
void* SSL_SESSION_set_time(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[336])(a, b, c, d);
}
void* SSL_SESSION_get0_peer(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[337])(a, b, c, d);
}
void* SSL_SESSION_set1_id_context(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[338])(a, b, c, d);
}
void* SSL_CTX_set_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[339])(a, b, c, d);
}
void* SSL_CTX_get_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[340])(a, b, c, d);
}
void* SSL_set_session_secret_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[341])(a, b, c, d);
}
void* SSL_set_session_ticket_ext_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[342])(a, b, c, d);
}
void* SSL_set_session_ticket_ext(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[343])(a, b, c, d);
}
void* SSL_CTX_sess_set_new_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[344])(a, b, c, d);
}
void* SSL_CTX_sess_get_new_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[345])(a, b, c, d);
}
void* SSL_CTX_sess_set_remove_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[346])(a, b, c, d);
}
void* SSL_CTX_sess_get_remove_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[347])(a, b, c, d);
}
void* SSL_CTX_sess_set_get_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[348])(a, b, c, d);
}
void* SSL_CTX_sess_get_get_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[349])(a, b, c, d);
}
void* SSL_CTX_set_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[350])(a, b, c, d);
}
void* SSL_CTX_get_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[351])(a, b, c, d);
}
void* SSL_CTX_set_client_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[352])(a, b, c, d);
}
void* SSL_CTX_get_client_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[353])(a, b, c, d);
}
void* SSL_CTX_set_channel_id_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[354])(a, b, c, d);
}
void* SSL_CTX_get_channel_id_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[355])(a, b, c, d);
}
void* PEM_read_bio_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[356])(a, b, c, d);
}
void* PEM_read_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[357])(a, b, c, d);
}
void* PEM_write_bio_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[358])(a, b, c, d);
}
void* PEM_write_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[359])(a, b, c, d);
}
void* SSL_state_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[360])(a, b, c, d);
}
void* SSL_rstate_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[361])(a, b, c, d);
}
void* SSL_state_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[362])(a, b, c, d);
}
void* SSL_alert_type_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[363])(a, b, c, d);
}
void* SSL_alert_type_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[364])(a, b, c, d);
}
void* SSL_alert_desc_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[365])(a, b, c, d);
}
void* SSL_alert_desc_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[366])(a, b, c, d);
}
void* SSL_rstate_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[367])(a, b, c, d);
}
void* SSL_SESSION_print(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[368])(a, b, c, d);
}
void* SSL_SESSION_print_fp(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[369])(a, b, c, d);
}
void* SSL_get_key_block_length(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[370])(a, b, c, d);
}
void* SSL_get_sigalgs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[371])(a, b, c, d);
}
void* SSL_get_shared_sigalgs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[372])(a, b, c, d);
}
void* __aeabi_unwind_cpp_pr2(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[373])(a, b, c, d);
}
void* __gnu_Unwind_Restore_VFP_D(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[374])(a, b, c, d);
}
void* __gnu_Unwind_Restore_VFP(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[375])(a, b, c, d);
}
void* __gnu_Unwind_Restore_VFP_D_16_to_31(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[376])(a, b, c, d);
}
void* __gnu_Unwind_Restore_WMMXD(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[377])(a, b, c, d);
}
void* __gnu_Unwind_Restore_WMMXC(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[378])(a, b, c, d);
}
void* restore_core_regs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[379])(a, b, c, d);
}
void* _Unwind_GetCFA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[380])(a, b, c, d);
}
void* __gnu_Unwind_RaiseException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[381])(a, b, c, d);
}
void* __gnu_Unwind_ForcedUnwind(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[382])(a, b, c, d);
}
void* __gnu_Unwind_Resume(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[383])(a, b, c, d);
}
void* __gnu_Unwind_Resume_or_Rethrow(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[384])(a, b, c, d);
}
void* _Unwind_Complete(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[385])(a, b, c, d);
}
void* _Unwind_DeleteException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[386])(a, b, c, d);
}
void* _Unwind_VRS_Get(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[387])(a, b, c, d);
}
void* _Unwind_VRS_Set(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[388])(a, b, c, d);
}
void* __gnu_Unwind_Backtrace(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[389])(a, b, c, d);
}
void* __gnu_unwind_execute(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[390])(a, b, c, d);
}
void* _Unwind_VRS_Pop(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[391])(a, b, c, d);
}
void* __gnu_Unwind_Save_VFP_D(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[392])(a, b, c, d);
}
void* __gnu_Unwind_Save_VFP(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[393])(a, b, c, d);
}
void* __gnu_Unwind_Save_VFP_D_16_to_31(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[394])(a, b, c, d);
}
void* __gnu_Unwind_Save_WMMXD(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[395])(a, b, c, d);
}
void* __gnu_Unwind_Save_WMMXC(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[396])(a, b, c, d);
}
void* __restore_core_regs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[397])(a, b, c, d);
}
void* ___Unwind_RaiseException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[398])(a, b, c, d);
}
void* _Unwind_RaiseException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[399])(a, b, c, d);
}
void* ___Unwind_Resume(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[400])(a, b, c, d);
}
void* _Unwind_Resume(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[401])(a, b, c, d);
}
void* ___Unwind_Resume_or_Rethrow(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[402])(a, b, c, d);
}
void* _Unwind_Resume_or_Rethrow(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[403])(a, b, c, d);
}
void* ___Unwind_ForcedUnwind(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[404])(a, b, c, d);
}
void* _Unwind_ForcedUnwind(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[405])(a, b, c, d);
}
void* ___Unwind_Backtrace(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[406])(a, b, c, d);
}
void* _Unwind_Backtrace(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[407])(a, b, c, d);
}
void* __gnu_unwind_frame(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[408])(a, b, c, d);
}
void* _Unwind_GetRegionStart(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[409])(a, b, c, d);
}
void* _Unwind_GetLanguageSpecificData(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[410])(a, b, c, d);
}
void* _Unwind_GetDataRelBase(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[411])(a, b, c, d);
}
void* _Unwind_GetTextRelBase(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[412])(a, b, c, d);
}
