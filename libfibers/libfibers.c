#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdbool.h>
#include "thread.h"
#include "libfibers.h"

#define STACK_DEFAULT_SIZE 8192

__thread int openfiber_local_file_desc;
#define NUM_FIBERS 30
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

int openfibers_ioctl_create_fiber(void (*addr)(void *), void* args)
{
    unsigned long size = STACK_DEFAULT_SIZE;
    struct fiber_request_t request = {
        .stack_address = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + size - 0x8,
        .start_address = addr,
        .stack_size = size,
        .start_args = args,
    };
    int res = ioctl(openfiber_local_file_desc, OPENFIBERS_IOCTL_CREATE_FIBER, (unsigned long)&request);
    if (res < 0)
    {
        perror("openfibers ioctl fiber create failed");
        return -1;
    }
    printf("openfibers fiber %d create done\n", res);
    return res;
}

int openfibers_ioctl_switch_to_fiber(fid_t fid)
{
    int res = ioctl(openfiber_local_file_desc, OPENFIBERS_IOCTL_SWITCH_TO_FIBER, fid);
    if (res < 0)
    {
        printf("openfibers ioctl fiber switch tid %d to %d failed\n", tid, fid);
        perror("");
        return -1;
    }
    return res;
}

int openfibers_ioctl_convert_to_fiber(void)
{
    openfiber_local_file_desc = open(OPENFIBERS_DEVICE_FILE_NAME, 0);
    if (openfiber_local_file_desc < 0)
    {
        perror("Can't open openfibers device file");
        return -1;
    }

    int res = ioctl(openfiber_local_file_desc, OPENFIBERS_IOCTL_CONVERT_TO_FIBER);
    if (res < 0)
    {
        perror("openfibers ioctl fiber conversion failed");
        return -1;
    }
    printf("openfibers fiber %d conversion done\n", res);
    return res;
}

void f0()
{
    while(1)
    {
        printf("tid %d in %d switching to %d\n", tid, fibers[0], fibers[1]);
        sleep(0.1);
        openfibers_ioctl_switch_to_fiber(fibers[1]);
    }
}

void f1()
{
    while (1)
    {
        printf("tid %d in %d switching to %d\n", tid, fibers[1], fibers[2]);
        sleep(0.1);
        openfibers_ioctl_switch_to_fiber(fibers[2]);
    }
}

void f2()
{
    while (1)
    {
        printf("tid %d in %d switching to %d\n", tid, fibers[2], fibers[0]);
        sleep(0.1);
        openfibers_ioctl_switch_to_fiber(fibers[0]);
    }
}

// Pick fibers randomly. This might return a fiber which is
// currently scheduled on another thread.
static int get_random_fiber(void)
{
    return random() % NUM_FIBERS;
}

void dummy_f(void* arg)
{
    unsigned int f;
    while (1)
    {
        f = get_random_fiber();
        printf("tid %d in %d switching to %d\n", tid, fibers[(unsigned long)arg], fibers[f]);
        sleep(0.5);
        openfibers_ioctl_switch_to_fiber(fibers[f]);
    }
}

static volatile bool init_complete;
// This function lives in an "abandoned" fiber: no-one will ever
// get back here!
static void *thread_initialization(void *args)
{
    unsigned int f;
    (void)args;

    fid_t fid = openfibers_ioctl_convert_to_fiber();

    while (!init_complete)
        ;

    while (true)
    {
        f = get_random_fiber();
        printf("WARNING thread %d: while switching to %d\n", tid, f);
        openfibers_ioctl_switch_to_fiber(fibers[f]);
    }
}

int main(int argc, char *argv[])
{
    int ret_val;
    unsigned long i;

    // Check if the number of fibers has been passed
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <num_threads>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Initialize pseudorandom generator
    srandom(time(0));

    fid_t f = openfibers_ioctl_convert_to_fiber();

    /*fibers[0] = openfibers_ioctl_create_fiber((unsigned long) f0);
    fibers[1] = openfibers_ioctl_create_fiber((unsigned long) f1);
    fibers[2] = openfibers_ioctl_create_fiber((unsigned long) f2);*/
    //openfibers_ioctl_ping(openfiber_local_file_desc);

    for (i = 0; i < NUM_FIBERS; i++)
    {
        fibers[i] = openfibers_ioctl_create_fiber(dummy_f, (void*)i);
    }
    sleep(1);
    create_threads(atoi(argv[1]), thread_initialization, NULL);

    init_complete = true;

    sleep(3);
    close(openfiber_local_file_desc);
    return 0;
}
