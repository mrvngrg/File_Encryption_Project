#include "../../headers/globals.h"
#include <stdbool.h>

Queue queue;
//const char *start_path = "/home/nicolas-berger/Documents/Safe/test_encryption";
// const char *start_path = "/home/drikson/University/os/test";
//const char *start_path = "/home/vboxuser/test";
const char *start_path = "/home/simon/Desktop/test";
//const char *start_path = "/home";

unsigned char key[16] = "qwertyuiopasdfgh";
bool encryption_active = false;