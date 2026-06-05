#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>

#define ALERT_FILE "/proc/security_driver_alert"

static int clear_alert(void)
{
    FILE *fp = fopen(ALERT_FILE, "w");
    if (!fp) {
        perror("fopen CLEAR");
        return -1;
    }

    fprintf(fp, "CLEAR\n");
    fclose(fp);
    return 0;
}

static int send_command(const char *cmd)
{
    FILE *fp = fopen(ALERT_FILE, "w");
    if (!fp) {
        perror("fopen command");
        return -1;
    }

    fprintf(fp, "%s\n", cmd);
    fclose(fp);
    return 0;
}

static int read_alert(int *pid_out,
                      char *proc_out,
                      size_t proc_size,
                      char *PID_path_out,
                      size_t PID_path_size)
{
    FILE *fp;
    char line[PATH_MAX + 256];
    int pid;
    char proc[64];
    char PID_path[PATH_MAX];

    fp = fopen(ALERT_FILE, "r");
    if (!fp) {
        perror("fopen alert file");
        return -1;
    }

    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0;
    }

    fclose(fp);

    if (strncmp(line, "NO_ALERT", 8) == 0)
        return 0;

    if (sscanf(line,
               "ALERT PID=%d PROC=%63s PID_PATH=%4095s",
               &pid,
               proc,
               PID_path) == 3) {
        *pid_out = pid;
        snprintf(proc_out, proc_size, "%s", proc);
        snprintf(PID_path_out, PID_path_size, "%s", PID_path);
        return 1;
    }

    return 0;
}

static void handle_alert(int pid, const char *proc_name, const char *PID_path)
{
    char answer[32];
    char choice;

    printf("\nSuspicious activity detected!\n");
    printf("Process: %s\n", proc_name);
    printf("PID: %d\n", pid);
    printf("PID path: %s\n", PID_path);
    printf("The kernel module already sent SIGSTOP to pause it.\n");

    while (1) {
        printf("Kill this process? (Y/N): ");
        fflush(stdout);

        if (!fgets(answer, sizeof(answer), stdin)) {
            printf("\nNo input. Continuing process.\n");
            kill(pid, SIGCONT);
            clear_alert();
            return;
        }

        choice = tolower((unsigned char)answer[0]);

        if (choice == 'y') {
            if (kill(pid, SIGKILL) == -1) {
                fprintf(stderr, "SIGKILL failed for PID %d: %s\n", pid, strerror(errno));
            } else {
                printf("Process %d killed.\n", pid);
            }
            clear_alert();
            return;
        }

        if (choice == 'n') {
            char cmd_buffer[PATH_MAX + 32];

            snprintf(cmd_buffer, sizeof(cmd_buffer), "ALLOW_PID_PATH %s", PID_path);
            send_command(cmd_buffer);

            if (kill(pid, SIGCONT) == -1) {
                fprintf(stderr, "SIGCONT failed for PID %d: %s\n", pid, strerror(errno));
            } else {
                printf("Process %d continued.\n", pid);
            }

            printf("PID path allowed: %s\n", PID_path);
            printf("It will not ask again for processes started from this same path.\n");
            return;
        }

        printf("Please enter Y or N.\n");
    }
}

int main(void)
{
    printf("User controller started. Watching %s\n", ALERT_FILE);
    printf("Press Ctrl+C to stop.\n");

    while (1) {
        int pid = -1;
        char proc[64] = {0};
        char PID_path[PATH_MAX] = {0};
        int result;

        result = read_alert(&pid, proc, sizeof(proc), PID_path, sizeof(PID_path));
        if (result < 0) {
            fprintf(stderr, "Could not read alert file. Is the kernel module loaded?\n");
            return 1;
        }

        if (result == 1)
            handle_alert(pid, proc, PID_path);

        sleep(1);
    }

    return 0;
}