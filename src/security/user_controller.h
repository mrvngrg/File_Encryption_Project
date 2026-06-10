#ifndef USER_CONTROLLER_H
#define USER_CONTROLLER_H

#include <stdbool.h>
#include <limits.h>

#define NETLINK_SECURITY 31

typedef struct SecurityAlert {
    bool pending;
    int pid;
    char proc[64];
    char pid_path[PATH_MAX];
} SecurityAlert;

int controller_read_alert(SecurityAlert *alert);

int controller_clear_alert(void);

int controller_kill_process(int pid);

int controller_allow_pid_path(const char *pid_path);

int controller_continue_process(int pid);

int controller_reset_lists(void);

void controller_close(void);

#endif
