#define _GNU_SOURCE

#include "user_controller.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

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

int controller_clear_alert(void)
{
    return send_command("CLEAR");
}

int controller_reset_lists(void)
{
    return send_command("RESET_LIST");
}

int controller_kill_process(int pid)
{
    if (kill(pid, SIGKILL) == -1) {
        fprintf(stderr, "SIGKILL failed for PID %d: %s\n",
                pid, strerror(errno));
        return -1;
    }

    controller_clear_alert();
    return 0;
}

int controller_continue_process(int pid)
{
    if (kill(pid, SIGCONT) == -1) {
        fprintf(stderr, "SIGCONT failed for PID %d: %s\n",
                pid, strerror(errno));
        return -1;
    }

    return 0;
}

int controller_allow_pid_path(const char *pid_path)
{
    char cmd[PATH_MAX + 32];

    if (!pid_path || pid_path[0] == '\0')
        return -1;

    snprintf(cmd, sizeof(cmd), "ALLOW_PID_PATH %s", pid_path);

    return send_command(cmd);
}

int controller_read_alert(SecurityAlert *alert)
{
    FILE *fp;
    char line[PATH_MAX + 256];
    int pid;
    char proc[64];
    int path_offset = 0;

    if (!alert)
        return -1;

    memset(alert, 0, sizeof(*alert));

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

    if (strncmp(line, "NO_ALERT", 8) == 0) {
        alert->pending = false;
        return 0;
    }

    if (sscanf(line,
               "ALERT PID=%d PROC=%63s PID_PATH=%n",
               &pid,
               proc,
               &path_offset) >= 2 && path_offset > 0) {

        alert->pending = true;
        alert->pid = pid;

        snprintf(alert->proc, sizeof(alert->proc), "%s", proc);
        snprintf(alert->pid_path,
                 sizeof(alert->pid_path),
                 "%s",
                 line + path_offset);

        alert->pid_path[strcspn(alert->pid_path, "\n")] = '\0';

        return 1;
    }

    return 0;
}