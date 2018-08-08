#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "libfibers.h"

#define STACK_DEFAULT_SIZE 4096

int file_desc;

void openfibers_ioctl_ping(int fd)
{
    if (ioctl(fd, OPENFIBERS_IOCTL_PING) == -1)
    {
        perror("openfibers ioctl ping failed");
        return;
    }
    printf("openfibers ping done\n");
}

int openfibers_ioctl_create_fiber(int fd, unsigned long addr)
{
    struct fiber_request_t request = {
        .stack_address = (unsigned long)mmap(NULL, STACK_DEFAULT_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + STACK_DEFAULT_SIZE,
        .start_address = addr,
    };
    int res = ioctl(fd, OPENFIBERS_IOCTL_CREATE_FIBER, (unsigned long)&request);
    if (res == -1)
    {
        perror("openfibers ioctl fiber create failed");
        return -1;
    }
    printf("openfibers fiber %d create done\n", res);
    return res;
}

int openfibers_ioctl_switch_to_fiber(int fd, unsigned long fid)
{
    int res = ioctl(fd, OPENFIBERS_IOCTL_SWITCH_TO_FIBER, fid);
    if (res < 0)
    {
        perror("openfibers ioctl fiber switch failed");
        return -1;
    }
    return res;
}

int openfibers_ioctl_convert_to_fiber(int fd)
{
    int res = ioctl(fd, OPENFIBERS_IOCTL_CONVERT_TO_FIBER);
    if (res < 0)
    {
        perror("openfibers ioctl fiber switch failed");
        return -1;
    }
    printf("openfibers fiber %d conversion done\n", res);
    return res;
}

void f1()
{
    while(1)
    {
        sleep(1);
        printf("1\n");
        openfibers_ioctl_switch_to_fiber(file_desc, 2);
    }
}

void f2()
{
    while (1)
    {
        sleep(1);
        printf("2\n");
        openfibers_ioctl_switch_to_fiber(file_desc, 1);
    }
}
int main(int argc, char *argv[])
{
    int ret_val;

    file_desc = open(OPENFIBERS_DEVICE_FILE_NAME, 0);
    if (file_desc < 0)
    {
        perror("Can't open openfibers device file");
        return -1;
    }

    openfibers_ioctl_convert_to_fiber(file_desc);

    openfibers_ioctl_create_fiber(file_desc, (unsigned long) f1);
    openfibers_ioctl_create_fiber(file_desc, (unsigned long)f2);
    openfibers_ioctl_ping(file_desc);

    openfibers_ioctl_switch_to_fiber(file_desc, 2);

    close(file_desc);
    return 0;
}
