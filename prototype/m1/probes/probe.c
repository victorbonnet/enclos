// Small, non-destructive probe helper for the milestone 1 prototype.
//
//   probe mach <service>                  bootstrap_look_up only; never sends a message
//   probe check <pid> <operation> [arg]   sandbox_check on another process, no side effect
//                                          (arg: a path for file-* ops, a name for mach-lookup)
//   probe unix <socket path>              connect() then close at once; sends nothing
//   probe tcp <ipv4> <port>               connect() then close at once
//
// Exit status: 0 = the route is open (lookup or connect succeeded, or
// sandbox_check says allowed), 1 = closed, 2 = usage error.
// Build: cc -O2 -o probe probe.c
#include <arpa/inet.h>
#include <errno.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Private but stable libsystem_sandbox API (used by Apple's own tools).
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
enum { FILTER_NONE = 0, FILTER_PATH = 1, FILTER_GLOBAL_NAME = 2, CHECK_NO_REPORT = 0x40000000 };

static int mach(const char *name) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, name, &port);
    if (kr == KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), port);
        printf("open: bootstrap_look_up(%s) succeeded\n", name);
        return 0;
    }
    printf("closed: bootstrap_look_up(%s) = %d (%s)\n", name, kr, bootstrap_strerror(kr));
    return 1;
}

static int check(pid_t pid, const char *op, const char *arg) {
    int type = FILTER_NONE;
    if (arg) type = strncmp(op, "mach-", 5) == 0 ? FILTER_GLOBAL_NAME : FILTER_PATH;
    int r = arg ? sandbox_check(pid, op, type | CHECK_NO_REPORT, arg)
                : sandbox_check(pid, op, type | CHECK_NO_REPORT);
    printf("%s: sandbox_check(%d, %s%s%s) = %d\n", r == 0 ? "open" : "closed", pid, op,
           arg ? ", " : "", arg ? arg : "", r);
    return r == 0 ? 0 : 1;
}

static int unix_connect(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
    int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    int e = errno;
    close(fd);
    if (r == 0) { printf("open: connect(%s) succeeded\n", path); return 0; }
    printf("closed: connect(%s): %s\n", path, strerror(e));
    return 1;
}

static int tcp_connect(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, ip, &sa.sin_addr);
    int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    int e = errno;
    close(fd);
    if (r == 0) { printf("open: connect(%s:%d) succeeded\n", ip, port); return 0; }
    printf("closed: connect(%s:%d): %s\n", ip, port, strerror(e));
    return 1;
}

int main(int argc, char **argv) {
    if (argc >= 3 && !strcmp(argv[1], "mach")) return mach(argv[2]);
    if (argc >= 4 && !strcmp(argv[1], "check")) return check(atoi(argv[2]), argv[3], argc > 4 ? argv[4] : NULL);
    if (argc >= 3 && !strcmp(argv[1], "unix")) return unix_connect(argv[2]);
    if (argc >= 4 && !strcmp(argv[1], "tcp")) return tcp_connect(argv[2], atoi(argv[3]));
    fprintf(stderr, "usage: probe mach <name> | check <pid> <op> [arg] | unix <path> | tcp <ip> <port>\n");
    return 2;
}
