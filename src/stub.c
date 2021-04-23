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
