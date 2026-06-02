#include "raylib.h"
#include "raygui.h"
#include "stdio.h"

int display_gui() {
    InitWindow(450, 600, "test");
    SetTargetFPS(60);

    int frame_count = 0;
    Image gif = LoadImageAnim("giphy.gif", &frame_count);
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

        BeginDrawing();
            ClearBackground((Color){ 255, 0, 0, 255 });
            DrawTexture(texture, 10, 10, WHITE);
            DrawText("Your Files are Encrypted, if you want", 10, texture.height + 20, 20, BLACK);
            DrawText("them back you must send 10 bicoins to me", 10, texture.height + 45, 20, BLACK);
            if (GuiButton((Rectangle){ 10, texture.height + 70, 400, 70 }, "Send 10 bitcoins")) {
                printf("button clicked\n");
            }
        EndDrawing();
    }

    UnloadImage(gif);
    UnloadTexture(texture);
    CloseWindow();
    return 0;
}