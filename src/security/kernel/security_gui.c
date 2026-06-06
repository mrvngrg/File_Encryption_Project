#include "raylib.h"

#define RAYGUI_IMPLEMENTATION
#include "../../encryption/raygui.h"

#include <stdio.h>
#include <string.h>

#include "user_controller.h"

int main(void)
{
    const int screen_width = 700;
    const int screen_height = 420;

    SecurityAlert alert = {0};

    double last_poll_time = 0.0;
    char status[256] = "Waiting for suspicious activity...";

    InitWindow(screen_width, screen_height, "Security Controller");
    SetTargetFPS(60);

    GuiLoadStyleDefault();
    GuiSetStyle(DEFAULT, TEXT_SIZE, 20);

    while (!WindowShouldClose()) {
        double now = GetTime();

        /*
         * Poll /proc every 0.5 seconds.
         * Do not read it every frame unnecessarily.
         */
        if (now - last_poll_time >= 0.5) {
            SecurityAlert new_alert;

            if (controller_read_alert(&new_alert) >= 0) {
                alert = new_alert;

                if (alert.pending) {
                    snprintf(status, sizeof(status),
                             "Suspicious process paused by kernel.");
                } else {
                    snprintf(status, sizeof(status),
                             "Waiting for suspicious activity...");
                }
            } else {
                snprintf(status, sizeof(status),
                         "Could not read %s. Is the kernel module loaded?",
                         ALERT_FILE);
            }

            last_poll_time = now;
        }

        BeginDrawing();
        ClearBackground(BLACK);

        DrawText("Security Controller", 30, 25, 28, RAYWHITE);
        DrawText(status, 30, 70, 18, DARKGRAY);

        if (alert.pending) {
            DrawRectangleLines(30, 110, 640, 210, RED);

            DrawText("Suspicious activity detected!", 50, 130, 24, RED);

            char pid_text[128];
            char proc_text[128];

            snprintf(pid_text, sizeof(pid_text), "PID: %d", alert.pid);
            snprintf(proc_text, sizeof(proc_text), "Process: %s", alert.proc);

            DrawText(proc_text, 50, 175, 20, RAYWHITE);
            DrawText(pid_text, 50, 205, 20, RAYWHITE);

            DrawText("Executable path:", 50, 235, 18, DARKGRAY);
            DrawText(alert.pid_path, 50, 260, 16, RAYWHITE);

            if (GuiButton((Rectangle){50, 340, 170, 45}, "Kill")) {
                if (controller_kill_process(alert.pid) == 0) {
                    snprintf(status, sizeof(status),
                             "Killed PID %d.", alert.pid);
                } else {
                    snprintf(status, sizeof(status),
                             "Failed to kill PID %d.", alert.pid);
                }

                alert.pending = false;
            }

            if (GuiButton((Rectangle){260, 340, 190, 45}, "Trust")) {
                if (controller_allow_pid_path(alert.pid_path) == 0) {
                    controller_continue_process(alert.pid);

                    snprintf(status, sizeof(status),
                             "Allowed path and continued PID %d.",
                             alert.pid);
                } else {
                    snprintf(status, sizeof(status),
                             "Failed to allow path.");
                }

                alert.pending = false;
            }

            if (GuiButton((Rectangle){490, 340, 150, 45}, "Continue")) {
                controller_clear_alert();

                snprintf(status, sizeof(status),
                         "Alert cleared.");

                alert.pending = false;
            }
        } else {
            DrawRectangleLines(30, 120, 640, 170, DARKGRAY);
            DrawText("No alert right now.", 50, 150, 24, RAYWHITE);
            DrawText("The GUI is watching /proc/security_driver_alert.",
                     50, 190, 18, DARKGRAY);

            if (GuiButton((Rectangle){50, 320, 190, 45}, "Reset Allowlist")) {
                if (controller_reset_lists() == 0) {
                    snprintf(status, sizeof(status),
                             "Allowlist reset.");
                } else {
                    snprintf(status, sizeof(status),
                             "Failed to reset allowlist.");
                }
            }
        }

        EndDrawing();
    }

    CloseWindow();

    return 0;
}