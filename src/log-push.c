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
