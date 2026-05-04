#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdbool.h>
#include "../../headers/queue.h"

#define BUF_LEN 4096
#define MAX_WATCHES 1024


//run with (for now): gcc src/encryption/watcher.c src/encryption/queue.c -o watcher

Queue queue;

const char *start_path = "/home/simon/Desktop/test"; // todo: mit start_path in main.c verbinden

char watchedPaths[MAX_WATCHES][1024];

bool is_temp_file(const char *name) {
    if (name[0] == '.') {
        return true;
    }

    size_t len = strlen(name);

    if (len > 5 && strcmp(name + len - 5, ".part") == 0) {
        return true;
    }

    return false;
}

//yoinked from frederic (ty bro)
void traverse(int ifd, const char *path) {

    int wd = inotify_add_watch(ifd, path, IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE);


    if (wd == -1) {
        perror("wd == -1");

    } else {
        strncpy(watchedPaths[wd], path, sizeof(watchedPaths[wd]));
        printf("watching: %s\n", path);
    }

    DIR *dir = opendir(path);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip current and parent directory
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char fullPath[1024];
        if (snprintf(fullPath, sizeof(fullPath), "%s/%s", path, entry->d_name) >= sizeof(fullPath)) {
            fprintf(stderr, "Path too long: %s/%s\n", path, entry->d_name);
            continue;
        }

        struct stat statbuf;
        if (stat(fullPath, &statbuf) == -1) {
            perror("stat");
            continue;
        }

        // skip links to avoid potential loops
        if (S_ISLNK(statbuf.st_mode)) {
            continue;
        }
        
        if (S_ISDIR(statbuf.st_mode)) {
            traverse(ifd, fullPath);
        }
    }

    closedir(dir);
}


int main() {

    initializeQueue(&queue);

    int ifd = inotify_init();

    traverse(ifd, start_path);

    char buf[BUF_LEN];

    while (true) {
        int len = read(ifd, buf, BUF_LEN);

        int i = 0;
        while (i < len) {
            struct inotify_event *event = (struct inotify_event *)&buf[i];

            if (event->len > 0) {
                char full_path[1024];
                snprintf(full_path, sizeof(full_path), "%s/%s", watchedPaths[event->wd], event->name);

                if (event->mask & IN_ISDIR) {
                    traverse(ifd, full_path);
                } else if (event->mask & IN_MOVED_TO) {
                    if (!is_temp_file(event->name)) {
                        printf("new file: %s\n", full_path);
                        enqueue(&queue, full_path); //todo: encrypt logik
                        print_queue(&queue);
                    }
                } else if (event->mask & IN_CLOSE_WRITE) {
                    if (!is_temp_file(event->name)) {
                        printf("new file: %s\n", full_path);
                        enqueue(&queue, full_path); //todo: encrypt logik
                        print_queue(&queue);
                    }
                }
            }

            i += sizeof(struct inotify_event) + event->len;
        }
    }
}