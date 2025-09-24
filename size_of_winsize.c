// size_of_winsize.c 查看返回的是 8byte
#include <stdio.h>
#include <sys/ioctl.h>
#include <termios.h>

int main() {
    printf("Size of struct winsize: %zu bytes\n", sizeof(struct winsize));
    return 0;
}


