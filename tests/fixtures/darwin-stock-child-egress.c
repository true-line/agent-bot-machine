#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void fail(const char *operation) {
    perror(operation);
    exit(1);
}

static void denied(int family, const struct sockaddr *address, socklen_t length,
                   int bind_socket) {
    int socket_fd = socket(family, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        if (errno == EPERM || errno == EACCES) return;
        fail("socket");
    }
    int result = bind_socket ? bind(socket_fd, address, length)
                             : connect(socket_fd, address, length);
    int saved_errno = errno;
    close(socket_fd);
    if (result != -1 || (saved_errno != EPERM && saved_errno != EACCES)) {
        fprintf(stderr, "unexpected sandbox result: result=%d errno=%d\n", result, saved_errno);
        exit(1);
    }
}

static struct sockaddr_un unix_address(const char *path) {
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path)) {
        fprintf(stderr, "Unix socket path too long\n");
        exit(1);
    }
    strcpy(address.sun_path, path);
    return address;
}

int main(int argc, char **argv) {
    if (argc != 9) {
        fprintf(stderr, "expected ports and six Unix socket paths\n");
        return 1;
    }
    struct sockaddr_in ipv4 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                               .sin_port = htons((unsigned short)atoi(argv[1]))};
    denied(AF_INET, (const struct sockaddr *)&ipv4, sizeof(ipv4), 0);
    struct sockaddr_in6 ipv6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT,
                                .sin6_port = htons((unsigned short)atoi(argv[2]))};
    denied(AF_INET6, (const struct sockaddr *)&ipv6, sizeof(ipv6), 0);
    for (int i = 3; i <= 6; i++) {
        struct sockaddr_un address = unix_address(argv[i]);
        denied(AF_UNIX, (const struct sockaddr *)&address, sizeof(address), 0);
    }
    struct sockaddr_un other_bind = unix_address(argv[8]);
    denied(AF_UNIX, (const struct sockaddr *)&other_bind, sizeof(other_bind), 1);

    struct sockaddr_un relay = unix_address(argv[7]);
    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0 || connect(socket_fd, (const struct sockaddr *)&relay, sizeof(relay)) < 0)
        fail("assigned relay connect");
    const char request[] = "GET fixture\n";
    const char reply[] = "fixture ready\n";
    if (write(socket_fd, request, sizeof(request) - 1) != sizeof(request) - 1)
        fail("assigned relay write");
    char received[sizeof(reply)] = {0};
    if (read(socket_fd, received, sizeof(reply) - 1) != sizeof(reply) - 1 ||
        memcmp(received, reply, sizeof(reply) - 1) != 0) {
        fprintf(stderr, "assigned relay returned unexpected reply\n");
        return 1;
    }
    close(socket_fd);
    return 0;
}
