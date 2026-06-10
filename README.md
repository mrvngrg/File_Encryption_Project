# Ransomware Simulation Project

> Warning: This project will encrypt all files in the configured directory. It is recommended to use a VM or a disposable folder for testing.

> This project is for educational purposes only!

This project implements a ransomware simulation in a Linux environment for educational purposes, with the goal of understanding both the attack and the defensive mechanisms.

## Dependencies
Install the OpenSSL library:

    sudo apt install libssl-dev

To install raylib and raygui: first install gcc, git, make and all required libraries:

    sudo apt install build-essential git
    sudo apt install libasound2-dev libx11-dev libxrandr-dev libxi-dev libgl1-mesa-dev libglu1-mesa-dev libxcursor-dev libxinerama-dev libwayland-dev libxkbcommon-dev

then clone the repo and compile raylib:

    git clone --depth 1 https://github.com/raysan5/raylib.git raylib
    cd raylib/src/
    make PLATFORM=PLATFORM_DESKTOP # To make the static version.
    make PLATFORM=PLATFORM_DESKTOP RAYLIB_LIBTYPE=SHARED # To make the dynamic shared version.

same thing for raygui

    git clone raysan5/raygui
    mv src/raygui.h src/raygui.c
    gcc -o raygui.so src/raygui.c -shared -fpic -DRAYGUI_IMPLEMENTATION -lraylib -lGL -lm -lpthread -ldl -lrt -lX11
    mv src/raygui.c src/raygui.h

## Configuration

In globals.c the target directory can be set.

    const char *start_path = "/home/youruser/Desktop/test";

Per default the server use localhost 127.0.0.1 and listen on port 8080

To use the server outside of localhost, the IP of the system that is running the server must be placed into the client.c file:

    char *IP = "someip";

you can change the speed of encryption by changing the value of THREADS_NUMBER in encryption/client.c.

## Build and Run

now you can compile and run our project

    make

    ./server                       # start server first
    ./calculator                   # this is the encryption executable that runs on the target machine

Server commands:

    encrypt;socketfd or all    - Encrypt all files
    decrypt;socketfd or all    - Decrypt all files
    kill;socketfd or all       - Terminate the client process
    list                       - List all current client connections

## security component as LKB module

Run carrefully since one crash or problem could crash the whole os.

    cd src/security/
    make
    make gui

    sudo insmod security.ko
    sudo rmmod security
