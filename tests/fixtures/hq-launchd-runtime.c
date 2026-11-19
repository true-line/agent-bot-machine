// Install fixture for the Machine approval and launchd lifecycle. The HQ
// repository exercises its production Ruby helper and Node entry separately.
#include <launch.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (!strcmp(argv[2], "check-owner-control") || !strcmp(argv[2], "status")) {
        char cwd[2];
        if (!getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/")) return 10;
    }
    if (!strcmp(argv[2], "check-owner-control")) {
        puts("{\"capability\":\"darwin-owner-control/v1\"}"); return 0;
    }
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strlcpy(addr.sun_path, "/private/var/agent-bot-hq-control.sock", sizeof(addr.sun_path));
    if (!strcmp(argv[2], "status")) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 3;
        FILE *response = fdopen(fd, "r"); char buf[512];
        if (!response || !fgets(buf, sizeof(buf), response)) return 4;
#ifdef MM_FIXTURE_FAIL_OWNER_STATUS
        // The owner reached the running fixture through its actual launchd socket.
        return 42;
#else
        puts(buf); return 0;
#endif
    }
    // run --home <state> --owner-account <owner>
    if (argc != 7 || strcmp(argv[2], "run") || strcmp(argv[3], "--home") || strcmp(argv[5], "--owner-account")) return 5;
    struct passwd *role = getpwnam("_agent-bot-hq");
    if (!role || role->pw_uid != geteuid()) return 6;
    mkdir(argv[4], 0700);
    struct passwd *owner = getpwnam(argv[6]);
    if (!owner) return 7;
    uid_t expected = owner->pw_uid;
    int *fds = NULL; size_t count = 0;
    if (launch_activate_socket("owner-control", &fds, &count) || count != 1) return 8;
    for (;;) {
        int conn = accept(fds[0], NULL, NULL); uid_t uid; gid_t gid;
        if (conn < 0) return 9;
        if (!getpeereid(conn, &uid, &gid) && uid == expected) {
            dprintf(conn, "{\"hq\":{\"account\":\"_agent-bot-hq\",\"sockets\":{\"ownerControl\":{\"account\":\"%s\",\"uid\":%u,\"path\":\"%s\",\"peer_check\":\"getpeereid\"}}}}\n", argv[6], uid, addr.sun_path);
        }
        close(conn);
    }
}
