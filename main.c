#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#include "headers/encryption.h"
#include "headers/thread.h"
#include "headers/globals.h"

const int THREADS_NUMBER = 8;

void traverse(const char *path) {
    // TODO: schould traverse the file system, starting with path and stock the path in a queue.

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
        snprintf(fullPath, sizeof(fullPath), "%s/%s", path, entry->d_name);

        struct stat statbuf;
        if (stat(fullPath, &statbuf) == -1) {
            perror("stat");
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            printf("Directory: %s\n", fullPath);
            traverse(fullPath);  // recursive call
        } else {
            //printf("File: %s\n", fullPath);
            // TODO: Skip problematic file 
            
            enqueue(&queue, fullPath);
        }
    }

    closedir(dir);
}

int main() {
    //RAND_bytes(key, sizeof(key));
    initializeQueue(&queue);

    //should start client

    traverse("/home/drikson/Documents/DPI/Lectures"); //change

    initialize_threads(THREADS_NUMBER);

    return 0; 
}
