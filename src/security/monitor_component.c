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
#include <dirent.h>

#define TIME_WINDOW 1
#define PIDS 256

#define WRITE_LIMIT 10
#define MODIFY_LIMIT 20
#define UNIQUE_FILE_LIMIT 10
#define HEADER_MISMATCH_LIMIT 3

#define FILES_PER_PID 15

volatile sig_atomic_t keep_running = 1;
char canary_path[PATH_MAX];
bool active_canary = false;

/*
 * Signal handler to safely catch exit commands

 */
void sigint_handler(int signum) {
    printf("\n\n[!] Stopping monitor... Cleaning up traps safely.\n");
    keep_running = 0; 
}

/*
 * Extracts the file extension from a given file path.
 */
static const char *get_file_extension(const char *path) {
    if (path == NULL) return NULL;
    const char *filename = strrchr(path, '/');
    if (filename != NULL) filename++;
    else filename = path;
    const char *dotOfExtension = strrchr(filename, '.');
    if (dotOfExtension == NULL || dotOfExtension == filename) return NULL;
    return dotOfExtension + 1;
}

/*
 * Compares a file extension against an expected string.
 */
static bool compare_extension_ignore_case(const char *extension, const char *expected_extension) {
    if (!extension || !expected_extension) return false;
    while (*extension && *expected_extension) {
        if (tolower((unsigned char)*extension) != tolower((unsigned char)*expected_extension)) return false;
        extension++;
        expected_extension++;
    }
    return *extension == '\0' && *expected_extension == '\0';
}

/*
 * Scans a directory for an existing PDF file to use as a cloning template.
 */
bool find_existing_pdf(const char *base_path, char *found_path, char *found_name) {
    DIR *dir = opendir(base_path);
    if (!dir) {
        printf("[-] Failed to open directory '%s'. OS Error: %s\n", base_path, strerror(errno));
        return false;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' || strstr(entry->d_name, "(copy)") != NULL) {
            continue;
        }

        char full_entry_path[PATH_MAX];
        snprintf(full_entry_path, PATH_MAX, "%s/%s", base_path, entry->d_name);

        struct stat path_stat;
        if (stat(full_entry_path, &path_stat) == 0) {
            if (S_ISREG(path_stat.st_mode)) { 
                const char *ext = get_file_extension(entry->d_name);
                if (ext && compare_extension_ignore_case(ext, "pdf")) {
                    strncpy(found_path, full_entry_path, PATH_MAX);
                    strncpy(found_name, entry->d_name, 256);
                    closedir(dir);
                    return true;
                }
            }
        }
    }
    closedir(dir);
    return false;
}

/*
 * Deploys a disguised Canary file by creating a bit-for-bit clone of an existing document.
 */
void deploy_canary(const char *base_path) {
    char src_pdf[PATH_MAX];
    char src_name[256];
    
    if (find_existing_pdf(base_path, src_pdf, src_name)) {
        
        char *dot = strrchr(src_name, '.');
        if (dot) {
            char base_name[256];
            size_t base_len = dot - src_name;
            if (base_len >= sizeof(base_name)) base_len = sizeof(base_name) - 1;
            
            strncpy(base_name, src_name, base_len);
            base_name[base_len] = '\0';
            
            snprintf(canary_path, PATH_MAX, "%s/%s(copy)%s", base_path, base_name, dot);
        } else {
            // Fallback if no extension exists
            snprintf(canary_path, PATH_MAX, "%s/%s(copy)", base_path, src_name);
        }
        
        unlink(canary_path); 
        
        printf("[*] Found existing PDF for cloning: %s\n", src_pdf);
        
        FILE *src = fopen(src_pdf, "rb");
        if (!src) {
            printf("[-] CRITICAL: Failed to open source file for reading.\n");
            printf("[-] OS Error: %s\n", strerror(errno));
            return;
        }

        FILE *dst = fopen(canary_path, "wb");
        if (!dst) {
            printf("[-] CRITICAL: Failed to create destination Canary file.\n");
            printf("[-] OS Error: %s\n", strerror(errno));
            fclose(src);
            return;
        }
        
        char buffer[4096];
        size_t bytes_read;
        size_t total_written = 0;

        while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
            size_t written = fwrite(buffer, 1, bytes_read, dst);
            if (written != bytes_read) {
                printf("[-] CRITICAL: Write error during file cloning.\n");
                printf("[-] OS Error: %s\n", strerror(errno));
                break;
            }
            total_written += written;
        }

        active_canary = true;
        printf("[+] Successfully cloned %zu bytes.\n", total_written);
        printf("[+] Deployed Disguised Canary: %s\n", canary_path);
        
        fclose(src);
        fclose(dst);
    } 
    else {
        printf("[-] ABORT: No existing PDFs found in directory to clone.\n");
        printf("[-] Monitor is running, but Canary trap is NOT active.\n");
    }
}

/*
 * Deletes the dynamically generated Canary file.
 */
void cleanup_canary() {
    if (active_canary) {
        if (unlink(canary_path) == 0) {
            printf("[+] Cleaned up Canary successfully.\n");
        }
    }
}

/*
 * Checks if a given file path matches the active Canary trap.
 */
bool is_canary_file(const char *file_path) {
    if (active_canary && strcmp(file_path, canary_path) == 0) {
        return true;
    }
    return false;
}


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
}*/

/*
* Ignores case when comparing the file extension with the expected one

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
*/

/*
* Checks if a file has the expected header based on its extension
*/
static bool file_has_expected_header(const char *file_path) {
    const char *extension = get_file_extension(file_path);
    if (!extension) return true;
    unsigned char buf[32];
    int fd = open(file_path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return true;
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) return true;

    if (compare_extension_ignore_case(extension, "pdf")) {
        return n >= 4 && memcmp(buf, "%PDF", 4) == 0;
    }
    if (compare_extension_ignore_case(extension, "png")) {
        static const unsigned char png_magic[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
        return n >= 8 && memcmp(buf, png_magic, 8) == 0;
    }
    if (compare_extension_ignore_case(extension, "jpg") || compare_extension_ignore_case(extension, "jpeg")) {
        return n >= 3 && buf[0] == 0xFF && buf[1] == 0xD8 && buf[2] == 0xFF;
    }
    if (compare_extension_ignore_case(extension, "gif")) {
        return n >= 6 && (memcmp(buf, "GIF87a", 6) == 0 || memcmp(buf, "GIF89a", 6) == 0);
    }
    if (compare_extension_ignore_case(extension, "zip")  ||
        compare_extension_ignore_case(extension, "docx") ||
        compare_extension_ignore_case(extension, "xlsx") ||
        compare_extension_ignore_case(extension, "pptx") ||
        compare_extension_ignore_case(extension, "odt")  ||
        compare_extension_ignore_case(extension, "ods")  ||
        compare_extension_ignore_case(extension, "odp")) {
        return n >= 2 && buf[0] == 'P' && buf[1] == 'K';

    }
    if (compare_extension_ignore_case(extension, "sqlite") || compare_extension_ignore_case(extension, "db")) {
        return n >= 15 && memcmp(buf, "SQLite format 3", 15) == 0;
    }
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

    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    deploy_canary(path);

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

    while (keep_running) {
        ssize_t len = read(fan_fd, buffer, sizeof(buffer));
        if (len == -1) {
            if (errno == EINTR) continue; 
            perror("read");
            break;
        }

        struct fanotify_event_metadata *metadata;
        for (metadata = (struct fanotify_event_metadata *)buffer;
             FAN_EVENT_OK(metadata, len);
             metadata = FAN_EVENT_NEXT(metadata, len)) {

            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                fprintf(stderr, "fanotify metadata version mismatch\n");
                keep_running = 0;
                break;
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
    cleanup_canary();
    printf("Monitor exited.\n");
    return 0;
}
