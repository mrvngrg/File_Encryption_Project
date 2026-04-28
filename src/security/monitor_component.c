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
#include <time.h>
#include <signal.h>
#include <ctype.h>

#define TIME_WINDOW 1
#define PIDS 256
#define WRITE_LIMIT 10
#define MODIFY_LIMIT 20


/*
* Prints the events in the mask
*/
static void print_mask(unsigned long long mask) {
    if (mask & FAN_MODIFY)      printf("MODIFY ");
    if (mask & FAN_CLOSE_WRITE) printf("CLOSE_WRITE ");
    if (mask & FAN_EVENT_ON_CHILD) printf("ON_CHILD ");
    //if (mask & FAN_ACCESS)      printf("ACCESS ");
    //if (mask & FAN_OPEN)        printf("OPEN ");
    //if (mask & FAN_CLOSE_NOWRITE) printf("CLOSE_NOWRITE ");
}


/*
* Structure that stores data about each process
*/
struct pid_activity {
    pid_t pid;
    int write_count;
    int modify_count;
    time_t timestamp;
};


/*
* List of processes being tracked
*/
static struct pid_activity PID_List[PIDS];

/*
* If a new process is detected: add it to the List (PID_List) and start tracking its activities.
* If the process is already being tracked: return a pointer to its entries.
*/
static struct pid_activity *process_tracker(pid_t pid) {
    for (int i = 0; i < PIDS; i++) {
        if (PID_List[i].pid == pid) {
            return &PID_List[i];
        }
    }

    for (int i = 0; i < PIDS; i++) {
        if (PID_List[i].pid == 0) {
            PID_List[i].pid = pid;
            PID_List[i].write_count = 0;
            PID_List[i].modify_count = 0;
            PID_List[i].timestamp = time(NULL);
            return &PID_List[i];
        }
    }

    return NULL;
}

/*
* Counts the number of times a process has been modified or written to files.
*/
static int activity(pid_t pid, unsigned long long mask) {
    time_t now = time(NULL);

    struct pid_activity *p = process_tracker(pid);
    if (p == NULL) {
        fprintf(stderr, "PID list is full\n");
        return 0;
    }

    if (now - p->timestamp > TIME_WINDOW) {
        p->write_count = 0;
        p->modify_count = 0;
        p->timestamp = now;
    }

    if (mask & FAN_CLOSE_WRITE) {
        p->write_count++;
    }

    if (mask & FAN_MODIFY) {
        p->modify_count++;
    }

    printf("TRACK PID=%d writes=%d modifies=%d\n",
           pid, p->write_count, p->modify_count);

    if (p->write_count >= WRITE_LIMIT || p->modify_count >= MODIFY_LIMIT) {
        return 1;
    }

    return 0;
}

/*
* If a suspicious acitivity is detected: Shows the process name, PID and asks the user if they
* want to kill the process.
*/
static void stop_activity(pid_t pid, const char *proc_name) {
    char answer[16];
    char choice;

    printf("\nSuspicious activity detected!\n");
    printf("Process: %s\n", proc_name);
    printf("PID: %d\n", pid);

    if (kill(pid, SIGSTOP) == -1) {
        perror("SIGSTOP failed");
        return;
    }

    do {
        printf("Kill this process? (Y/N): ");
        fflush(stdout);

        if (fgets(answer, sizeof(answer), stdin) == NULL) {
        kill(pid, SIGCONT);
        return;
        }

        choice = tolower((unsigned char)answer[0]);
        if (choice != 'y' && choice != 'n') {
            printf("Please enter 'Y' or 'N'.\n");
        }

    } while (choice != 'y' && choice != 'n');

    if (choice == 'y') {
        if (kill(pid, SIGKILL) == -1) {
            perror("SIGKILL failed");
            kill(pid, SIGCONT);
        } else {
            printf("Process %d killed.\n", pid);
        }
    } else  {
        if (kill(pid, SIGCONT) == -1) {
            perror("SIGCONT failed");
        } else {
            printf("Process %d continued.\n", pid);
        }
    } 
}

/*
* Initializes fanotify, marks the specified path for monitoring, and enters a loop to read events.
*/
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
        FAN_MODIFY |
        FAN_CLOSE_WRITE |
        FAN_EVENT_ON_CHILD;
        //FAN_OPEN |
        //FAN_ACCESS |
        //FAN_CLOSE_NOWRITE |

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

            if (activity(metadata->pid, metadata->mask)) {
                stop_activity(metadata->pid, proc_name);
            }

            close(metadata->fd);
        }
    }

    close(fan_fd);
    return 0;
}