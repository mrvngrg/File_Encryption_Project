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
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
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

#define PROC_NAME "security_driver_alert"

struct pid_activity {
    pid_t pid;
    bool active;
    int unique_dir_count;
    int unique_file_count;
    char dirs[MAX_DIRS][256];
    char files[MAX_DIRS][256];
    ktime_t timestamp;
};

static struct pid_activity pid_list[MAX_PIDS];
static DEFINE_SPINLOCK(pid_lock);

/* One-alert storage for communication with user space */
static DEFINE_SPINLOCK(alert_lock);
static pid_t alert_pid = -1;
static char alert_proc[TASK_COMM_LEN];
static bool alert_pending = false;

#define MAX_WHITELIST 32
static char whitelisted_procs[MAX_WHITELIST][TASK_COMM_LEN];
static int whitelist_count = 0;
static DEFINE_SPINLOCK(whitelist_lock);

//static struct proc_dir_entry *alert_proc_entry;

/*
* 
*/
static struct pid_activity *get_or_create(pid_t pid)
{
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

static void count_unique_dir(struct pid_activity *p, const char *path)
{
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

static void count_unique_file(struct pid_activity *p, const char *path)
{
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

static void save_alert(pid_t pid, const char *proc_name)
{
    unsigned long flags;

    spin_lock_irqsave(&alert_lock, flags);

    alert_pid = pid;
    strscpy(alert_proc, proc_name, sizeof(alert_proc));
    alert_pending = true;

    spin_unlock_irqrestore(&alert_lock, flags);
}

static void stop_process(pid_t pid, const char *proc_name)
{
    struct task_struct *task;

    rcu_read_lock();

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        pr_warn("security_driver: sending SIGSTOP to PID=%d PROC=%s\n",
                pid, proc_name);
        send_sig(SIGSTOP, task, 0);
    } else {
        pr_warn("security_driver: could not find PID=%d PROC=%s\n",
                pid, proc_name);
    }

    rcu_read_unlock();
}

static ssize_t alert_read(struct file *file, char __user *buf,
                          size_t count, loff_t *ppos)
{
    char message[128];
    int len;
    unsigned long flags;
    pid_t pid_copy;
    char proc_copy[TASK_COMM_LEN];
    bool pending_copy;

    if (*ppos > 0)
        return 0;

    spin_lock_irqsave(&alert_lock, flags);

    pid_copy = alert_pid;
    strscpy(proc_copy, alert_proc, sizeof(proc_copy));
    pending_copy = alert_pending;

    spin_unlock_irqrestore(&alert_lock, flags);

    if (!pending_copy) {
        len = scnprintf(message, sizeof(message), "NO_ALERT\n");
    } else {
        len = scnprintf(message, sizeof(message),
                        "ALERT PID=%d PROC=%s\n",
                        pid_copy, proc_copy);
    }

    return simple_read_from_buffer(buf, count, ppos, message, len);
}

static ssize_t alert_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos)
{
    char cmd[64];
    unsigned long flags;
    size_t len;

    len = min(count, sizeof(cmd) - 1);

    if (copy_from_user(cmd, buf, len))
        return -EFAULT;

    cmd[len] = '\0';

    if (strncmp(cmd, "CLEAR", 5) == 0) {
        spin_lock_irqsave(&alert_lock, flags);
        alert_pid = -1;
        alert_proc[0] = '\0';
        alert_pending = false;
        spin_unlock_irqrestore(&alert_lock, flags);

        //pr_info("security_driver: alert cleared by user space\n");
    }
    else if (strncmp(cmd, "ALLOW_PROC ", 11) == 0) {
        char *pname = cmd + 11;
        char *nl = strchr(pname, '\n');
        if (nl) *nl = '\0'; // Clean newline

        // Add to whitelist
        spin_lock_irqsave(&whitelist_lock, flags);
        if (whitelist_count < MAX_WHITELIST) {
            strscpy(whitelisted_procs[whitelist_count], pname, TASK_COMM_LEN);
            whitelist_count++;
            pr_info("security_driver: WHITELISTED process: %s\n", pname);
        }
        spin_unlock_irqrestore(&whitelist_lock, flags);

        // Auto-clear alert
        spin_lock_irqsave(&alert_lock, flags);
        alert_pid = -1; alert_proc[0] = '\0'; alert_pending = false;
        spin_unlock_irqrestore(&alert_lock, flags);
    }
    else if (strncmp(cmd, "RESET_LIST", 10) == 0) {
        // Wipe the whitelist when user-space connects
        spin_lock_irqsave(&whitelist_lock, flags);
        whitelist_count = 0;
        spin_unlock_irqrestore(&whitelist_lock, flags);
        
        spin_lock_irqsave(&alert_lock, flags);
        alert_pid = -1; alert_proc[0] = '\0'; alert_pending = false;
        spin_unlock_irqrestore(&alert_lock, flags);
        
        pr_info("security_driver: Whitelist RESET by user space.\n");
    }

    return count;
}

static const struct proc_ops alert_proc_ops = {
    .proc_read = alert_read,
    .proc_write = alert_write,
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
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
    int i;

    if (!current->mm)
        return 0;

    if (!file)
        return 0;

    spin_lock_irqsave(&whitelist_lock, flags);
    for (i = 0; i < whitelist_count; i++) {
        if (strncmp(whitelisted_procs[i], proc_name, TASK_COMM_LEN) == 0) {
            spin_unlock_irqrestore(&whitelist_lock, flags);
            return 0; // Completely ignore this process
        }
    }
    spin_unlock_irqrestore(&whitelist_lock, flags);

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
                entry->active = false; // Prevent spam
                suspicious = true;
                suspicious_pid = pid;
                strscpy(suspicious_proc, proc_name, sizeof(suspicious_proc));
            }
        }
    }
    spin_unlock_irqrestore(&pid_lock, flags);
    kfree(path_buf);

    if (suspicious) {
        save_alert(suspicious_pid, suspicious_proc);
        stop_process(suspicious_pid, suspicious_proc);
    }
    return 0;
}

static struct kprobe kp = { .symbol_name = "vfs_write", .pre_handler = handler_pre, };

static int __init mod_init(void) {
    int ret;
    memset(pid_list, 0, sizeof(pid_list));
    alert_proc[0] = '\0';

    if (!proc_create(PROC_NAME, 0666, NULL, &alert_proc_ops)) return -ENOMEM;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        remove_proc_entry(PROC_NAME, NULL);
        return ret;
    }
    pr_info("security_driver: loaded successfully\n");
    return 0;
}

static void __exit mod_exit(void) {
    unregister_kprobe(&kp);
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("security_driver: unloaded\n");
}
module_init(mod_init);
module_exit(mod_exit);