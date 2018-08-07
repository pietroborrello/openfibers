#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>

#include "libfibers.h"

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
    int res = ioctl(fd, OPENFIBERS_IOCTL_CREATE_FIBER, addr);
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
    printf("openfibers fiber %d switch done\n", res);
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

int main(int argc, char *argv[])
{
    int file_desc, ret_val;

    file_desc = open(OPENFIBERS_DEVICE_FILE_NAME, 0);
    if (file_desc < 0)
    {
        perror("Can't open openfibers device file");
        return -1;
    }

    openfibers_ioctl_convert_to_fiber(file_desc);

    openfibers_ioctl_create_fiber(file_desc, (unsigned long) main);
    openfibers_ioctl_create_fiber(file_desc, (unsigned long) 0x10000);
    openfibers_ioctl_create_fiber(file_desc, (unsigned long)0x20000);
    openfibers_ioctl_ping(file_desc);

    openfibers_ioctl_switch_to_fiber(file_desc, 2);
    openfibers_ioctl_switch_to_fiber(file_desc, 0);
    openfibers_ioctl_switch_to_fiber(file_desc, 7);

    close(file_desc);
    return 0;
}
