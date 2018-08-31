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

__thread int libfibers_local_file_desc;
#define NUM_FIBERS 30
static fid_t fibers[NUM_FIBERS];

// Simplistic allocation for FLS
long libfibers_ioctl_fls_alloc(void)
{
    int res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_FLS_ALLOC);
    return res;
}

// Get a FLS value
long libfibers_ioctl_fls_get(long idx)
{
    int res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_FLS_GET, idx);
    return res;
}

// Dummy: we don't actually free FLS here...
bool libfibers_ioctl_fls_free(long idx)
{
    int res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_FLS_FREE, idx);
    return res;
}

// Store a value in FLS storage
void libfibers_ioctl_fls_set(long idx, long value)
{
    struct fls_request_t request = {
        .idx = idx,
        .value = value,
    };
    ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_FLS_SET, (unsigned long)&request);
}

void libfibers_ioctl_ping(int fd)
{
    if (ioctl(fd, OPENFIBERS_IOCTL_PING) == -1)
    {
        printf("libfibers ioctl ping failed");
        return;
    }
    printf("libfibers ping done\n");
}

int libfibers_ioctl_create_fiber(void (*addr)(void *), void* args)
{
    unsigned long size = STACK_DEFAULT_SIZE;
    struct fiber_request_t request = {
        .stack_address = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + size - 0x8,
        .start_address = addr,
        .stack_size = size,
        .start_args = args,
    };
    int res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_CREATE_FIBER, (unsigned long)&request);
    if (res < 0)
    {
        printf("libfibers ioctl fiber create failed");
        return -1;
    }
    printf("libfibers fiber %d create done\n", res);
    return res;
}

int libfibers_ioctl_switch_to_fiber(fid_t fid)
{
    // tell gcc you will clobber them, so let him save and restore them for us during fiber switches
    asm volatile(
        "\n\t" ::
            : "%rbp", "%rbx", "%r12", "%r13", "%r14", "%r15");
    int res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_SWITCH_TO_FIBER, fid);
    
    if (res < 0)
    {
        printf("libfibers ioctl fiber switch tid %d to %d failed\n", tid, fid);
        //printf("");
        return -1;
    }
    return res;
}

int libfibers_ioctl_convert_to_fiber(void)
{
    libfibers_local_file_desc = open(OPENFIBERS_DEVICE_FILE_NAME, 0);
    if (libfibers_local_file_desc < 0)
    {
        printf("Can't open libfibers device file");
        return -1;
    }

    int res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_CONVERT_TO_FIBER);
    if (res < 0)
    {
        printf("libfibers ioctl fiber conversion failed");
        return -1;
    }
    printf("libfibers fiber %d conversion done\n", res);
    return res;
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
        libfibers_ioctl_switch_to_fiber(fibers[f]);
    }
}

static volatile bool init_complete;
// This function lives in an "abandoned" fiber: no-one will ever
// get back here!
static void *thread_initialization(void *args)
{
    unsigned int f;
    (void)args;

    fid_t fid = libfibers_ioctl_convert_to_fiber();

    while (!init_complete)
        ;

    while (true)
    {
        f = get_random_fiber();
        printf("WARNING thread %d: while switching to %d\n", tid, f);
        libfibers_ioctl_switch_to_fiber(fibers[f]);
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

    fid_t f = libfibers_ioctl_convert_to_fiber();

    //libfibers_ioctl_ping(libfibers_local_file_desc);

    for (i = 0; i < NUM_FIBERS; i++)
    {
        fibers[i] = libfibers_ioctl_create_fiber(dummy_f, (void*)i);
    }
    sleep(1);
    create_threads(atoi(argv[1]), thread_initialization, NULL);

    init_complete = true;

    sleep(3);
    close(libfibers_local_file_desc);
    return 0;
}

