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

int main(int argc, char *argv[])
{
    int file_desc, ret_val;

    file_desc = open(OPENFIBERS_DEVICE_FILE_NAME, 0);
    if (file_desc < 0)
    {
        perror("Can't open openfibers device file");
        return -1;
    }

    openfibers_ioctl_ping(file_desc);
    openfibers_ioctl_ping(file_desc);

    close(file_desc);
    return 0;
}
