#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

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

static int read_alert(int *pid_out, char *proc_out, size_t proc_size)
{
    FILE *fp;
    char line[256];
    int pid;
    char proc[64];

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

    if (sscanf(line, "ALERT PID=%d PROC=%63s", &pid, proc) == 2) {
        *pid_out = pid;
        snprintf(proc_out, proc_size, "%s", proc);
        return 1;
    }

    return 0;
}

static void handle_alert(int pid, const char *proc_name)
{
    char answer[32];
    char choice;

    printf("\nSuspicious activity detected!\n");
    printf("Process: %s\n", proc_name);
    printf("PID: %d\n", pid);
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
            if (kill(pid, SIGCONT) == -1) {
                fprintf(stderr, "SIGCONT failed for PID %d: %s\n", pid, strerror(errno));
            } else {
                printf("Process %d continued.\n", pid);
            }
            snprintf(cmd_buffer, sizeof(cmd_buffer), "ALLOW_PROC %s", proc_name);
            send_command(cmd_buffer);
            
            printf("[-] Process '%s' allowed. The Kernel will ignore it for the rest of this session.\n", proc_name);
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
        int result;

        result = read_alert(&pid, proc, sizeof(proc));
        if (result < 0) {
            fprintf(stderr, "Could not read alert file. Is the kernel module loaded?\n");
            return 1;
        }

        if (result == 1)
            handle_alert(pid, proc);

        sleep(1);
    }

    return 0;
}
