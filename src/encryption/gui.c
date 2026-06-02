#include "raylib.h"
#include "raygui.h"

int display_gui() {
    InitWindow(400, 200, "test");
    SetTargetFPS(60);

    int frame_count = 0;
    Image gif = LoadImageAnim("/home/drikson/University/os/File_Encryption_Project/giphy.gif", &frame_count);
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
            ClearBackground(RAYWHITE);
            DrawTexture(texture, 10, 10, WHITE);
        EndDrawing();
    }

    // Unload both at the end
    UnloadImage(gif);
    UnloadTexture(texture);
    CloseWindow();
    return 0;
}