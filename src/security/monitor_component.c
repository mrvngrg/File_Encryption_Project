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
#include <stdbool.h>

#define TIME_WINDOW 1
#define PIDS 256

#define WRITE_LIMIT 10
#define MODIFY_LIMIT 20
#define UNIQUE_FILE_LIMIT 10
#define HEADER_MISMATCH_LIMIT 3

#define FILES_PER_PID 15


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
    int unique_file_count;
    int header_mismatch_count;

    char files[FILES_PER_PID][PATH_MAX];
    time_t timestamp;
    bool pass;
};


/*
* List of processes being tracked
*/
static struct pid_activity PID_List[PIDS];


/*
* If a new process is detected: add it to the List (PID_List) and start tracking its activities.
* If the process is already being tracked: return a pointer to its entries
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
            PID_List[i].header_mismatch_count = 0;
            PID_List[i].timestamp = time(NULL);
            PID_List[i].pass = false;
            PID_List[i].unique_file_count = 0;
            return &PID_List[i];
        }
    }

    return NULL;
}


static void count_unique_file(struct pid_activity *p, const char *file_path) {
    if (!file_path || strcmp(file_path, "(unknown)") == 0) {
        return;
    }

    for (int i = 0; i < p->unique_file_count; i++) {
        if (strcmp(p->files[i], file_path) == 0) {
            return;
        }
    }

    if (p->unique_file_count < FILES_PER_PID) {
        strncpy(p->files[p->unique_file_count], file_path, PATH_MAX - 1);
        p->files[p->unique_file_count][PATH_MAX - 1] = '\0';
        p->unique_file_count++;
    }
}
/*
* Get extension from path
*/
static const char *get_file_extension(const char *path) {
    if (path == NULL) {
        return NULL;
    }

    const char *filename = strrchr(path, '/');

    if (filename != NULL) {
        filename++;
    } else {
        filename = path;
    }

    const char *dotOfExtension = strrchr(filename, '.');

    if (dotOfExtension == NULL || dotOfExtension == filename) {
        return NULL;
    }

    return dotOfExtension + 1;
}

/*
* Ignores case when comparing the file extension with the expected one
*/
static bool compare_extension_ignore_case(const char *extension, const char *expected_extension) {
    if (!extension || !expected_extension) {
        return false;
    }

    while (*extension && *expected_extension) {

        if (tolower((unsigned char)*extension) !=
            tolower((unsigned char)*expected_extension)) {
            return false;
        }

        extension++;
        expected_extension++;
    }

    return *extension == '\0' &&
           *expected_extension == '\0';
}


/*
* Checks if a file has the expected header based on its extension
*/
static bool file_has_expected_header(const char *file_path) {
    const char *extension = get_file_extension(file_path);

    if (!extension) {
        return true;
    }

    unsigned char buf[32];

    int fd = open(file_path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return true;
    }

    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);

    if (n <= 0) {
        return true;
    }

    /*
     * PDF: %PDF
     */
    if (compare_extension_ignore_case(extension, "pdf")) {
        return n >= 4 && memcmp(buf, "%PDF", 4) == 0;
    }

    /*
     * PNG: 89 50 4E 47 0D 0A 1A 0A
     */
    if (compare_extension_ignore_case(extension, "png")) {
        static const unsigned char png_magic[8] = {
            0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A
        };

        return n >= 8 && memcmp(buf, png_magic, 8) == 0;
    }

    /*
     * JPEG: FF D8 FF
     */
    if (compare_extension_ignore_case(extension, "jpg") || compare_extension_ignore_case(extension, "jpeg")) {
        return n >= 3 &&
               buf[0] == 0xFF &&
               buf[1] == 0xD8 &&
               buf[2] == 0xFF;
    }

    /*
     * GIF: GIF87a or GIF89a
     */
    if (compare_extension_ignore_case(extension, "gif")) {
        return n >= 6 &&
               (memcmp(buf, "GIF87a", 6) == 0 ||
                memcmp(buf, "GIF89a", 6) == 0);
    }

    /*
     * ZIP-based formats: zip, docx, xlsx, pptx, odt, ods, odp
     * normally: PK
     */
    if (compare_extension_ignore_case(extension, "zip")  ||
        compare_extension_ignore_case(extension, "docx") ||
        compare_extension_ignore_case(extension, "xlsx") ||
        compare_extension_ignore_case(extension, "pptx") ||
        compare_extension_ignore_case(extension, "odt")  ||
        compare_extension_ignore_case(extension, "ods")  ||
        compare_extension_ignore_case(extension, "odp")) {
        return n >= 2 && buf[0] == 'P' && buf[1] == 'K';
    }

    /*
     * SQLite databases
     */
    if (compare_extension_ignore_case(extension, "sqlite") || compare_extension_ignore_case(extension, "db")) {
        return n >= 15 && memcmp(buf, "SQLite format 3", 15) == 0;
    }

    /*
     * Unknown extension: Do not count as suspicious
     */
    return true;
}

/*
 * Returns true if a known file type no longer has its expected header
 */
static bool header_mismatch(const char *file_path) {
    if (!file_path || strcmp(file_path, "(unknown)") == 0) {
        return false;
    }

    return !file_has_expected_header(file_path);
}

/*
* Counts the number of times a process has been modified or written to files
*/
static int activity(pid_t pid, unsigned long long mask, const char *file_path) {
    time_t now = time(NULL);

    struct pid_activity *p = process_tracker(pid);
    if (p == NULL) {
        fprintf(stderr, "PID list is full\n");
        return 0;
    }

    if(p->pass) {
        return 0;
    }

    if (now - p->timestamp > TIME_WINDOW) {
        p->write_count = 0;
        p->modify_count = 0;
        p->unique_file_count = 0;
        p->header_mismatch_count = 0;
        p->timestamp = now;
    }

    if (mask & FAN_CLOSE_WRITE) {
        p->write_count++;

        if (header_mismatch(file_path)) {
            p->header_mismatch_count++;
        }
    }

    if (mask & (FAN_MODIFY | FAN_CLOSE_WRITE)) {
        count_unique_file(p, file_path);
    }

    if (mask & FAN_MODIFY) {
        p->modify_count++;
    }

    printf("TRACK PID=%d writes=%d modifies=%d unique_files=%d/%d header_mismatch=%d/%d\n",
           pid, p->write_count, p->modify_count, p->unique_file_count, UNIQUE_FILE_LIMIT, p->header_mismatch_count, HEADER_MISMATCH_LIMIT);

    if (p->write_count >= WRITE_LIMIT &&
        p->modify_count >= MODIFY_LIMIT &&
        p->unique_file_count >= UNIQUE_FILE_LIMIT &&
        p->header_mismatch_count >= HEADER_MISMATCH_LIMIT) {
        return 1;
    }

    return 0;
}


/*
* If a suspicious acitivity is detected: Shows the process name, PID and asks the user if they
* want to kill the process
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
        struct pid_activity *p = process_tracker(pid);
        if(p->pass == false) {
            p->pass = true;
        }
        if (kill(pid, SIGCONT) == -1) {
            perror("SIGCONT failed");
        } else {
            printf("Process %d continued.\n", pid);
        }
    } 
}

/*
* Initializes fanotify, marks the specified path for monitoring, and enters a loop to read events
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

            if (activity(metadata->pid, metadata->mask, file_path)) {
                stop_activity(metadata->pid, proc_name);
            }

            close(metadata->fd);
        }
    }

    close(fan_fd);
    return 0;
}