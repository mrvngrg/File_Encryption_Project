# Ransomware Simulation Project

> Warning: This project will encrypt all files in the configured directory. It is recommended to use a VM or a disposable folder for testing.

> This project is for educational purposes only!

This project implements a ransomware simulation in a Linux environment for educational purposes, with the goal of understanding both the attack and the defensive mechanisms.



## Configuration

In globals.c the target directory can be set.

    const char *start_path = "/home/youruser/Desktop/test";

To use the server outside of localhost, the IP of the system that is running the server must be placed into the client.c file:

    char *IP = "someip";

## Build and Run

    make all

    ./server                       # start server first
    ./client                       # run on target machine
    sudo ./monitor /path/to/watch  # optional detection tool
Server commands:

    encrypt;socketfd or all    - Encrypt all files
    decrypt;socketfd or all    - Decrypt all files
    kill;socketfd or all       - Terminate the client process
    list                       - List all current client connections
