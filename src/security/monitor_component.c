#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <sys/fanotify.h>
#include <sys/types.h>
#include <sys/stat.h>

static void print_mask(unsigned long long mask) {
    if (mask & FAN_ACCESS)      printf("ACCESS ");
    if (mask & FAN_OPEN)        printf("OPEN ");
    if (mask & FAN_MODIFY)      printf("MODIFY ");
    if (mask & FAN_CLOSE_WRITE) printf("CLOSE_WRITE ");
    if (mask & FAN_CLOSE_NOWRITE) printf("CLOSE_NOWRITE ");
    if (mask & FAN_EVENT_ON_CHILD) printf("ON_CHILD ");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path-to-watch>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];

    int fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE);
    if (fan_fd == -1) {
        perror("fanotify_init");
        return 1;
    }

    unsigned long long mask =
        FAN_OPEN |
        FAN_ACCESS |
        FAN_MODIFY |
        FAN_CLOSE_WRITE |
        FAN_CLOSE_NOWRITE |
        FAN_EVENT_ON_CHILD;

    if (fanotify_mark(fan_fd,
                      FAN_MARK_ADD | FAN_MARK_MOUNT,
                      mask,
                      AT_FDCWD,
                      path) == -1) {
        perror("fanotify_mark");
        close(fan_fd);
        return 1;
    }

    printf("Monitoring: %s\n", path);
    printf("Press Ctrl+C to stop.\n");

    char buffer[8192];

    for (;;) {
        ssize_t len = read(fan_fd, buffer, sizeof(buffer));
        if (len == -1) {
            if (errno == EINTR)
                continue;
            perror("read");
            break;
        }

        struct fanotify_event_metadata *metadata;
        for (metadata = (struct fanotify_event_metadata *)buffer;
             FAN_EVENT_OK(metadata, len);
             metadata = FAN_EVENT_NEXT(metadata, len)) {

            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                fprintf(stderr, "fanotify metadata version mismatch\n");
                close(fan_fd);
                return 1;
            }

            if (metadata->fd == FAN_NOFD) {
                continue;
            }

            char proc_path[64];
            char file_path[PATH_MAX];
            char fd_path[64];

            snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", metadata->fd);
            ssize_t path_len = readlink(fd_path, file_path, sizeof(file_path) - 1);
            if (path_len >= 0) {
                file_path[path_len] = '\0';
            } else {
                strcpy(file_path, "(unknown)");
            }

            snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", metadata->pid);
            FILE *fp = fopen(proc_path, "r");
            char proc_name[256] = "(unknown)";
            if (fp) {
                if (fgets(proc_name, sizeof(proc_name), fp)) {
                    proc_name[strcspn(proc_name, "\n")] = '\0';
                }
                fclose(fp);
            }

            printf("PID=%d PROC=%s FILE=%s EVENTS=", metadata->pid, proc_name, file_path);
            print_mask(metadata->mask);
            printf("\n");

            close(metadata->fd);
        }
    }

    close(fan_fd);
    return 0;
}