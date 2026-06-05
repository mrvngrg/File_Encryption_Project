#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("File operation detector");

#define MAX_PIDS 256
#define MAX_DIRS 32
#define UNIQUE_DIR_LIMIT 5      // more than 5 different dirs = suspicious
#define UNIQUE_FILE_LIMIT 10    // more than 10 different files = suspicious
#define TIME_WINDOW_MS 3000     // within 3 seconds

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

static struct pid_activity *get_or_create(pid_t pid) {
    int i;
    for (i = 0; i < MAX_PIDS; i++)
        if (pid_list[i].active && pid_list[i].pid == pid)
            return &pid_list[i];

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
    // extract parent directory from path
    char dir[256];
    char *last_slash;
    int i;

    strncpy(dir, path, 255);
    dir[255] = '\0';
    last_slash = strrchr(dir, '/');
    if (last_slash) *last_slash = '\0';

    for (i = 0; i < p->unique_dir_count; i++)
        if (strncmp(p->dirs[i], dir, 255) == 0)
            return; // already seen this dir

    if (p->unique_dir_count < MAX_DIRS) {
        strncpy(p->dirs[p->unique_dir_count], dir, 255);
        p->unique_dir_count++;
    }
}

static void count_unique_file(struct pid_activity *p, const char *path) {
    int i;
    for (i = 0; i < p->unique_file_count; i++)
        if (strncmp(p->files[i], path, 255) == 0)
            return; // already seen this file

    if (p->unique_file_count < MAX_DIRS) {
        strncpy(p->files[p->unique_file_count], path, 255);
        p->unique_file_count++;
    }
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    struct file *file = (struct file *)regs->di;
    pid_t pid = current->pid;
    const char *proc_name = current->comm;
    char *path_buf;
    char *path;
    unsigned long flags;
    s64 elapsed;

    if (!current->mm)
        return 0;

    if (!file || !file->f_path.dentry)
        return 0;

    path_buf = kmalloc(256, GFP_ATOMIC);
    if (!path_buf)
        return 0;

    path = dentry_path_raw(file->f_path.dentry, path_buf, 256);
    if (IS_ERR(path)) {
        kfree(path_buf);
        return 0;
    }

    // only /home/
    if (strncmp(path, "/home/", 6) != 0) {
        kfree(path_buf);
        return 0;
    }

    spin_lock_irqsave(&pid_lock, flags);

    struct pid_activity *entry = get_or_create(pid);
    if (entry) {
        // reset if time window passed
        elapsed = ktime_to_ms(ktime_sub(ktime_get(), entry->timestamp));
        if (elapsed > TIME_WINDOW_MS) {
            entry->unique_dir_count = 0;
            entry->unique_file_count = 0;
            entry->timestamp = ktime_get();
        }

        count_unique_dir(entry, path);
        count_unique_file(entry, path);

        printk(KERN_INFO "security_driver: PID=%d PROC=%s dirs=%d files=%d\n",
               pid, proc_name,
               entry->unique_dir_count,
               entry->unique_file_count);

        // DETECTION
        if (entry->unique_dir_count >= UNIQUE_DIR_LIMIT &&
            entry->unique_file_count >= UNIQUE_FILE_LIMIT) {

            printk(KERN_WARNING "security_driver: SUSPICIOUS PID=%d PROC=%s dirs=%d files=%d\n",
                   pid, proc_name,
                   entry->unique_dir_count,
                   entry->unique_file_count);

            // mark as detected so we don't alert twice
            entry->active = false;

            spin_unlock_irqrestore(&pid_lock, flags);
            kfree(path_buf);
            return 0;
        }
    }

    spin_unlock_irqrestore(&pid_lock, flags);
    kfree(path_buf);
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "vfs_write",
    .pre_handler = handler_pre,
};

static int __init mod_init(void) {
    int ret;
    memset(pid_list, 0, sizeof(pid_list));
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe failed: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "security_driver: loaded\n");
    return 0;
}

static void __exit mod_exit(void) {
    unregister_kprobe(&kp);
    printk(KERN_INFO "security_driver: unloaded\n");
}

module_init(mod_init);
module_exit(mod_exit);