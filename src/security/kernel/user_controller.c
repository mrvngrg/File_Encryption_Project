#define _GNU_SOURCE

#include "user_controller.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>

static int nl_sock = -1;
static struct sockaddr_nl kernel_addr;
static SecurityAlert cached_alert;

static int parse_alert_message(const char *line, SecurityAlert *alert)
{
    int pid;
    char proc[64];
    int path_offset = 0;

    if (!line || !alert)
        return -1;

    if (strncmp(line, "NO_ALERT", 8) == 0) {
        memset(alert, 0, sizeof(*alert));
        alert->pending = false;
        return 0;
    }

    if (sscanf(line,
               "ALERT PID=%d PROC=%63s PID_PATH=%n",
               &pid,
               proc,
               &path_offset) >= 2 && path_offset > 0) {

        memset(alert, 0, sizeof(*alert));
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

    return -1;
}

static int nl_send_command(const char *cmd)
{
    struct nlmsghdr *nlh;
    struct iovec iov;
    struct msghdr msg;
    size_t cmd_len;
    int ret;

    if (!cmd)
        return -1;

    if (nl_sock < 0)
        return -1;

    cmd_len = strlen(cmd) + 1;

    nlh = calloc(1, NLMSG_SPACE(cmd_len));
    if (!nlh)
        return -1;

    nlh->nlmsg_len = NLMSG_SPACE(cmd_len);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    memcpy(NLMSG_DATA(nlh), cmd, cmd_len);

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &kernel_addr;
    msg.msg_namelen = sizeof(kernel_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = sendmsg(nl_sock, &msg, 0);
    if (ret < 0)
        perror("sendmsg netlink");

    free(nlh);
    return ret < 0 ? -1 : 0;
}

static int controller_init(void)
{
    struct sockaddr_nl local_addr;

    if (nl_sock >= 0)
        return 0;

    nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_SECURITY);
    if (nl_sock < 0) {
        perror("socket netlink");
        return -1;
    }

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.nl_family = AF_NETLINK;
    local_addr.nl_pid = getpid();

    if (bind(nl_sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind netlink");
        close(nl_sock);
        nl_sock = -1;
        return -1;
    }

    memset(&kernel_addr, 0, sizeof(kernel_addr));
    kernel_addr.nl_family = AF_NETLINK;
    kernel_addr.nl_pid = 0;      /* kernel */
    kernel_addr.nl_groups = 0;

    memset(&cached_alert, 0, sizeof(cached_alert));

    return nl_send_command("REGISTER");
}

static int receive_one_message(SecurityAlert *alert)
{
    char buffer[NLMSG_SPACE(PATH_MAX + 256)];
    struct iovec iov;
    struct msghdr msg;
    struct sockaddr_nl src_addr;
    struct nlmsghdr *nlh;
    int ret;

    memset(buffer, 0, sizeof(buffer));
    memset(&src_addr, 0, sizeof(src_addr));

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &src_addr;
    msg.msg_namelen = sizeof(src_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(nl_sock, &msg, MSG_DONTWAIT);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        perror("recvmsg netlink");
        return -1;
    }

    nlh = (struct nlmsghdr *)buffer;
    if (nlh->nlmsg_len < NLMSG_HDRLEN)
        return -1;

    return parse_alert_message((const char *)NLMSG_DATA(nlh), alert);
}

int controller_read_alert(SecurityAlert *alert)
{
    SecurityAlert new_alert;
    int ret;
    int got_message = 0;

    if (!alert)
        return -1;

    if (controller_init() < 0)
        return -1;

    /* Ask the kernel for the current state, but do not block the GUI. */
    nl_send_command("GET_ALERT");

    while ((ret = receive_one_message(&new_alert)) != 0) {
        if (ret < 0)
            return -1;

        cached_alert = new_alert;
        got_message = 1;
    }

    (void)got_message;
    *alert = cached_alert;
    return cached_alert.pending ? 1 : 0;
}

int controller_clear_alert(void)
{
    if (controller_init() < 0)
        return -1;

    memset(&cached_alert, 0, sizeof(cached_alert));
    return nl_send_command("CLEAR");
}

int controller_reset_lists(void)
{
    if (controller_init() < 0)
        return -1;

    memset(&cached_alert, 0, sizeof(cached_alert));
    return nl_send_command("RESET_LIST");
}

int controller_kill_process(int pid)
{
    char cmd[64];

    if (controller_init() < 0)
        return -1;

    snprintf(cmd, sizeof(cmd), "KILL %d", pid);
    memset(&cached_alert, 0, sizeof(cached_alert));
    return nl_send_command(cmd);
}

int controller_continue_process(int pid)
{
    char cmd[64];

    if (controller_init() < 0)
        return -1;

    snprintf(cmd, sizeof(cmd), "CONTINUE %d", pid);
    memset(&cached_alert, 0, sizeof(cached_alert));
    return nl_send_command(cmd);
}

int controller_allow_pid_path(const char *pid_path)
{
    char cmd[PATH_MAX + 32];

    if (!pid_path || pid_path[0] == '\0')
        return -1;

    if (controller_init() < 0)
        return -1;

    snprintf(cmd, sizeof(cmd), "ALLOW_PID_PATH %s", pid_path);
    memset(&cached_alert, 0, sizeof(cached_alert));
    return nl_send_command(cmd);
}

void controller_close(void)
{
    if (nl_sock >= 0) {
        close(nl_sock);
        nl_sock = -1;
    }
}
