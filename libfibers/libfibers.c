#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdbool.h>
#include "thread.h"
#include "libfibers.h"

#define STACK_DEFAULT_SIZE 4096

int file_desc;
#define NUM_FIBERS 3
static fid_t fibers[NUM_FIBERS];

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
    unsigned long size = STACK_DEFAULT_SIZE;
    struct fiber_request_t request = {
        .stack_address = (unsigned long)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + size,
        .start_address = addr,
        .stack_size = size,
        .start_parameters = 0,
    };
    int res = ioctl(fd, OPENFIBERS_IOCTL_CREATE_FIBER, (unsigned long)&request);
    if (res < 0)
    {
        perror("openfibers ioctl fiber create failed");
        return -1;
    }
    printf("openfibers fiber %d create done\n", res);
    return res;
}

int openfibers_ioctl_switch_to_fiber(int fd, fid_t fid)
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
        printf("tid %d in 1 switching to 2\n", tid);
        sleep(1);
        openfibers_ioctl_switch_to_fiber(file_desc, fibers[1]);
    }
}

void f2()
{
    while (1)
    {
        printf("tid %d in 2 switching to 3\n", tid);
        sleep(1);
        openfibers_ioctl_switch_to_fiber(file_desc, fibers[2]);
    }
}

void f3()
{
    while (1)
    {
        printf("tid %d in 3 switching to 1\n", tid);
        sleep(1);
        openfibers_ioctl_switch_to_fiber(file_desc, fibers[0]);
    }
}

static volatile bool init_complete;
// This function lives in an "abandoned" fiber: no-one will ever
// get back here!
static void *thread_initialization(void *args)
{
    unsigned int f;
    (void)args;

    fid_t fid = openfibers_ioctl_convert_to_fiber(file_desc);

    while (!init_complete)
        ;
    while (true)
    {
        printf("%d: while switching to %d\n", tid, fibers[2]);
        openfibers_ioctl_switch_to_fiber(file_desc, fibers[2]);
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

    create_threads(2, thread_initialization, NULL);

    fid_t f = openfibers_ioctl_convert_to_fiber(file_desc);

    fibers[0] = openfibers_ioctl_create_fiber(file_desc, (unsigned long) f1);
    fibers[1] = openfibers_ioctl_create_fiber(file_desc, (unsigned long)f2);
    fibers[2] = openfibers_ioctl_create_fiber(file_desc, (unsigned long)f3);
    //openfibers_ioctl_ping(file_desc);

    init_complete = true;

    sleep(10);
    close(file_desc);
    return 0;
}
