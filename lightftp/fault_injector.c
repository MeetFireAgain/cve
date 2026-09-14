#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>

// Function pointers for original syscalls
typedef ssize_t (*real_write_t)(int fd, const void *buf, size_t count);
typedef int (*real_open_t)(const char *pathname, int flags, ...);
typedef int (*real_open64_t)(const char *pathname, int flags, ...);

static real_write_t real_write = NULL;
static real_open_t real_open = NULL;
static real_open64_t real_open64 = NULL;

static int target_fd = -1;
static size_t bytes_written_to_target = 0;
// Trigger error after writing this many bytes
static const size_t ERROR_THRESHOLD = 512; 

// Initializer to resolve symbols
__attribute__((constructor))
void init(void) {
    real_write = (real_write_t)dlsym(RTLD_NEXT, "write");
    real_open = (real_open_t)dlsym(RTLD_NEXT, "open");
    real_open64 = (real_open64_t)dlsym(RTLD_NEXT, "open64");
}

// Logic for flagging the target FD
void check_path(int fd, const char *pathname) {
    if (fd >= 0 && pathname && strstr(pathname, "vuln_test.txt") != NULL) {
        target_fd = fd;
        fprintf(stderr, "[INJECTOR] Targeting FD %d for %s (via open*)\n", fd, pathname);
    }
}

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (!real_open) init();

    int fd;
    if (flags & O_CREAT) fd = real_open(pathname, flags, mode);
    else fd = real_open(pathname, flags);
    
    check_path(fd, pathname);
    return fd;
}

int open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (!real_open64) init();

    int fd;
    if (flags & O_CREAT) fd = real_open64(pathname, flags, mode);
    else fd = real_open64(pathname, flags);
    
    check_path(fd, pathname);
    return fd;
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (!real_write) init();

    if (fd == target_fd && fd != -1) {
        if (bytes_written_to_target + count > ERROR_THRESHOLD) {
            // Write partial or fail immediately
            // Let's simulate immediate failure once we cross threshold
            size_t allowed = 0;
            if (bytes_written_to_target < ERROR_THRESHOLD) {
                allowed = ERROR_THRESHOLD - bytes_written_to_target;
            }
            
            if (allowed > 0) {
                 // Allow writing up to threshold
                 ssize_t ret = real_write(fd, buf, allowed);
                 if (ret > 0) bytes_written_to_target += ret;
                 return ret;
            } else {
                // Fail now!
                fprintf(stderr, "[INJECTOR] Injecting ENOSPC error on FD %d!\n", fd);
                errno = ENOSPC;
                return -1;
            }
        }
        
        // Track written bytes
        ssize_t ret = real_write(fd, buf, count);
        if (ret > 0) bytes_written_to_target += ret;
        return ret;
    }

    return real_write(fd, buf, count);
}
