#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/pid.h>
#include <linux/signal.h>
#include <linux/limits.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("Kernel file operation detector with user-space alert controller");

#define MAX_PIDS 256
#define MAX_DIRS 32
#define UNIQUE_DIR_LIMIT 5
#define UNIQUE_FILE_LIMIT 10
#define TIME_WINDOW_MS 3000
#define MAX_ALLOWED_PIDS 256
#define MAX_ALLOWED_PID_PATHS 64

#define NETLINK_SECURITY 31

static char allowed_PID_paths[MAX_ALLOWED_PID_PATHS][PATH_MAX];
static int allowed_PID_path_count = 0;
static DEFINE_SPINLOCK(allowed_PID_path_lock);

static char alert_PID_path[PATH_MAX];

static struct sock *nl_sk;
static u32 user_portid;

static pid_t allowed_pids[MAX_ALLOWED_PIDS];
static int allowed_pid_count = 0;
static DEFINE_SPINLOCK(allowed_pid_lock);

struct pid_activity {
    pid_t pid;
    bool active;
    int unique_dir_count;
    int unique_file_count;
    char dirs[MAX_DIRS][256];
    char files[MAX_DIRS][256];
    ktime_t timestamp;
};

static bool PID_path_is_allowed(const char *PID_path) {
    int i;

    for (i = 0; i < allowed_PID_path_count; i++) {
        if (strncmp(allowed_PID_paths[i], PID_path, PATH_MAX) == 0)
            return true;
    }

    return false;
}

static int get_current_PID_path(char *out, size_t out_size) {
    struct mm_struct *mm;
    struct file *exe_file;
    char *buf;
    char *path;
    int ret = -ENOENT;

    if (!out || out_size == 0)
        return -EINVAL;

    out[0] = '\0';

    mm = get_task_mm(current);
    if (!mm)
        return -ENOENT;

    exe_file = mm->exe_file;
    if (!exe_file) {
        mmput(mm);
        return -ENOENT;
    }

    buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf) {
        mmput(mm);
        return -ENOMEM;
    }

    path = d_path(&exe_file->f_path, buf, PATH_MAX);
    if (!IS_ERR(path)) {
        strscpy(out, path, out_size);
        ret = 0;
    }

    kfree(buf);
    mmput(mm);
    return ret;
}

static struct pid_activity pid_list[MAX_PIDS];
static DEFINE_SPINLOCK(pid_lock);

static DEFINE_SPINLOCK(alert_lock);
static pid_t alert_pid = -1;
static char alert_proc[TASK_COMM_LEN];
static bool alert_pending = false;

static bool pid_is_allowed(pid_t pid) {
    int i;

    for (i = 0; i < allowed_pid_count; i++) {
        if (allowed_pids[i] == pid)
            return true;
    }

    return false;
}

static struct pid_activity *get_or_create(pid_t pid) {
    int i;

    for (i = 0; i < MAX_PIDS; i++) {
        if (pid_list[i].active && pid_list[i].pid == pid)
            return &pid_list[i];
    }

    for (i = 0; i < MAX_PIDS; i++) {
        if (!pid_list[i].active) {
            memset(&pid_list[i], 0, sizeof(struct pid_activity));
            pid_list[i].pid = pid;
            pid_list[i].active = true;
            pid_list[i].timestamp = ktime_get();
            return &pid_list[i];
        }
    }

    return NULL;
}

static void count_unique_dir(struct pid_activity *p, const char *path) {
    char dir[256];
    char *last_slash;
    int i;

    strscpy(dir, path, sizeof(dir));

    last_slash = strrchr(dir, '/');
    if (last_slash)
        *last_slash = '\0';

    for (i = 0; i < p->unique_dir_count; i++) {
        if (strncmp(p->dirs[i], dir, sizeof(p->dirs[i])) == 0)
            return;
    }

    if (p->unique_dir_count < MAX_DIRS) {
        strscpy(p->dirs[p->unique_dir_count], dir,
                sizeof(p->dirs[p->unique_dir_count]));
        p->unique_dir_count++;
    }
}

static void count_unique_file(struct pid_activity *p, const char *path) {
    int i;

    for (i = 0; i < p->unique_file_count; i++) {
        if (strncmp(p->files[i], path, sizeof(p->files[i])) == 0)
            return;
    }

    if (p->unique_file_count < MAX_DIRS) {
        strscpy(p->files[p->unique_file_count], path,
                sizeof(p->files[p->unique_file_count]));
        p->unique_file_count++;
    }
}

static void save_alert(pid_t pid, const char *proc_name, const char *PID_path) {
    unsigned long flags;

    spin_lock_irqsave(&alert_lock, flags);

    alert_pid = pid;
    strscpy(alert_proc, proc_name, sizeof(alert_proc));
    strscpy(alert_PID_path, PID_path, sizeof(alert_PID_path));
    alert_pending = true;

    spin_unlock_irqrestore(&alert_lock, flags);
}

static int signal_process(pid_t pid, int sig, const char *reason) {
    struct task_struct *task;
    int ret = -ESRCH;

    rcu_read_lock();

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        pr_info("security_driver: sending signal %d to PID=%d (%s)\n",
                sig, pid, reason ? reason : "no reason");
        ret = send_sig(sig, task, 0);
    } else {
        pr_warn("security_driver: could not find PID=%d for signal %d\n",
                pid, sig);
    }

    rcu_read_unlock();
    return ret;
}

static void stop_process(pid_t pid, const char *proc_name){
    signal_process(pid, SIGSTOP, proc_name);
}

static void clear_current_alert(void) {
    unsigned long flags;

    spin_lock_irqsave(&alert_lock, flags);
    alert_pid = -1;
    alert_proc[0] = '\0';
    alert_PID_path[0] = '\0';
    alert_pending = false;
    spin_unlock_irqrestore(&alert_lock, flags);
}

static void reset_allowlists(void) {
    unsigned long flags;

    spin_lock_irqsave(&allowed_pid_lock, flags);
    allowed_pid_count = 0;
    spin_unlock_irqrestore(&allowed_pid_lock, flags);

    spin_lock_irqsave(&allowed_PID_path_lock, flags);
    allowed_PID_path_count = 0;
    spin_unlock_irqrestore(&allowed_PID_path_lock, flags);

    clear_current_alert();
    pr_info("security_driver: allowlists RESET by user space.\n");
}

static void allow_pid_path(const char *PID_path) {
    unsigned long flags;
    int i;
    bool already_saved = false;

    if (!PID_path || PID_path[0] == '\0')
        return;

    spin_lock_irqsave(&allowed_PID_path_lock, flags);

    for (i = 0; i < allowed_PID_path_count; i++) {
        if (strncmp(allowed_PID_paths[i], PID_path, PATH_MAX) == 0) {
            already_saved = true;
            break;
        }
    }

    if (!already_saved && allowed_PID_path_count < MAX_ALLOWED_PID_PATHS) {
        strscpy(allowed_PID_paths[allowed_PID_path_count], PID_path, PATH_MAX);
        allowed_PID_path_count++;
        pr_info("security_driver: allowed PID_path=%s\n", PID_path);
    }

    spin_unlock_irqrestore(&allowed_PID_path_lock, flags);
}

static void build_alert_message(char *message, size_t size) {
    unsigned long flags;
    pid_t pid_copy;
    char proc_copy[TASK_COMM_LEN];
    char PID_path_copy[PATH_MAX];
    bool pending_copy;

    spin_lock_irqsave(&alert_lock, flags);
    pid_copy = alert_pid;
    strscpy(proc_copy, alert_proc, sizeof(proc_copy));
    strscpy(PID_path_copy, alert_PID_path, sizeof(PID_path_copy));
    pending_copy = alert_pending;
    spin_unlock_irqrestore(&alert_lock, flags);

    if (!pending_copy) {
        scnprintf(message, size, "NO_ALERT");
    } else {
        scnprintf(message, size, "ALERT PID=%d PROC=%s PID_PATH=%s",
                  pid_copy, proc_copy, PID_path_copy);
    }
}

static int nl_send_to_user(const char *message) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size;

    if (!nl_sk || user_portid == 0 || !message)
        return -ENODEV;

    msg_size = strlen(message) + 1;

    skb = nlmsg_new(msg_size, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        return -ENOMEM;
    }

    memcpy(nlmsg_data(nlh), message, msg_size);

    return nlmsg_unicast(nl_sk, skb, user_portid);
}

static void nl_send_current_alert(void) {
    char message[PATH_MAX + 128];

    build_alert_message(message, sizeof(message));
    nl_send_to_user(message);
}

static void nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    char *cmd;
    pid_t pid;
    char *PID_path;
    char *nl;

    if (!skb)
        return;

    nlh = nlmsg_hdr(skb);
    if (!nlh || nlmsg_len(nlh) <= 0)
        return;

    user_portid = NETLINK_CB(skb).portid;
    cmd = nlmsg_data(nlh);

    if (strncmp(cmd, "REGISTER", 8) == 0) {
        pr_info("security_driver: user controller registered portid=%u\n",
                user_portid);
        nl_send_current_alert();
    }

    else if (strncmp(cmd, "GET_ALERT", 9) == 0) {
        nl_send_current_alert();
    }

    else if (strncmp(cmd, "CLEAR", 5) == 0) {
        clear_current_alert();
        nl_send_current_alert();
    }

    else if (strncmp(cmd, "RESET_LIST", 10) == 0) {
        reset_allowlists();
        nl_send_current_alert();
    }

    else if (strncmp(cmd, "KILL ", 5) == 0) {
        if (kstrtoint(cmd + 5, 10, &pid) == 0 && pid > 0)
            signal_process(pid, SIGKILL, "user kill");

        clear_current_alert();
        nl_send_current_alert();
    }

    else if (strncmp(cmd, "CONTINUE ", 9) == 0) {
        if (kstrtoint(cmd + 9, 10, &pid) == 0 && pid > 0)
            signal_process(pid, SIGCONT, "user continue");

        clear_current_alert();
        nl_send_current_alert();
    }

    else if (strncmp(cmd, "ALLOW_PID_PATH ", 15) == 0) {
        PID_path = cmd + 15;
        nl = strchr(PID_path, '\n');
        if (nl)
            *nl = '\0';

        allow_pid_path(PID_path);

        {
            unsigned long flags;

            spin_lock_irqsave(&alert_lock, flags);
            pid = alert_pid;
            spin_unlock_irqrestore(&alert_lock, flags);
        }

        if (pid > 0)
            signal_process(pid, SIGCONT, "trusted path");

        clear_current_alert();
        nl_send_current_alert();
    }
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
#if defined(CONFIG_X86_64)
    struct file *file = (struct file *)regs->di;
#else
    struct file *file = NULL;
#endif
    pid_t pid = current->pid;
    const char *proc_name = current->comm;
    char *path_buf;
    char *path;
    unsigned long flags;
    s64 elapsed;
    bool suspicious = false;
    pid_t suspicious_pid = -1;
    char suspicious_proc[TASK_COMM_LEN];
    char PID_path[PATH_MAX];

    spin_lock_irqsave(&allowed_pid_lock, flags);
    if (pid_is_allowed(pid)) {
        spin_unlock_irqrestore(&allowed_pid_lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&allowed_pid_lock, flags);

    if (!current->mm)
        return 0;

    if (!file)
        return 0;

    if (get_current_PID_path(PID_path, sizeof(PID_path)) == 0) {
    spin_lock_irqsave(&allowed_PID_path_lock, flags);
    if (PID_path_is_allowed(PID_path)) {
        spin_unlock_irqrestore(&allowed_PID_path_lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&allowed_PID_path_lock, flags);
    } else {
    PID_path[0] = '\0';
    }

    path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!path_buf) return 0;

    path = d_path(&file->f_path, path_buf, PATH_MAX);
    if (IS_ERR(path)) { kfree(path_buf); return 0; }
    if (strncmp(path, "/home/", 6) != 0) { kfree(path_buf); return 0; }

    spin_lock_irqsave(&pid_lock, flags);
    {
        struct pid_activity *entry = get_or_create(pid);
        if (entry) {
            elapsed = ktime_to_ms(ktime_sub(ktime_get(), entry->timestamp));
            if (elapsed > TIME_WINDOW_MS) {
                entry->unique_dir_count = 0; entry->unique_file_count = 0;
                memset(entry->dirs, 0, sizeof(entry->dirs)); memset(entry->files, 0, sizeof(entry->files));
                entry->timestamp = ktime_get();
            }

            count_unique_dir(entry, path); count_unique_file(entry, path);

            if (entry->unique_dir_count >= UNIQUE_DIR_LIMIT && entry->unique_file_count >= UNIQUE_FILE_LIMIT) {
                entry->active = false;
                suspicious = true;
                suspicious_pid = pid;
                strscpy(suspicious_proc, proc_name, sizeof(suspicious_proc));
            }
        }
    }
    spin_unlock_irqrestore(&pid_lock, flags);
    kfree(path_buf);

    if (suspicious) {
        save_alert(suspicious_pid, suspicious_proc, PID_path);
        stop_process(suspicious_pid, suspicious_proc);
        nl_send_current_alert();
    }
    return 0;
}

static struct kprobe kp = { .symbol_name = "vfs_write", .pre_handler = handler_pre, };

static int __init mod_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };
    int ret;

    memset(pid_list, 0, sizeof(pid_list));
    alert_proc[0] = '\0';
    alert_PID_path[0] = '\0';
    user_portid = 0;

    nl_sk = netlink_kernel_create(&init_net, NETLINK_SECURITY, &cfg);
    if (!nl_sk) {
        pr_err("security_driver: failed to create netlink socket\n");
        return -ENOMEM;
    }

    ret = register_kprobe(&kp);
    if (ret < 0) {
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
        return ret;
    }

    pr_info("security_driver: loaded successfully with netlink protocol %d\n",
            NETLINK_SECURITY);
    return 0;
}

static void __exit mod_exit(void) {
    unregister_kprobe(&kp);

    if (nl_sk)
        netlink_kernel_release(nl_sk);

    pr_info("security_driver: unloaded\n");
}
module_init(mod_init);
module_exit(mod_exit);