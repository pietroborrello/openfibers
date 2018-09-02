#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include "thread.h"

#define OPENFIBERS_IOCTL_MAGIC 'o'

#define OPENFIBERS_IOCTL_PING _IO(OPENFIBERS_IOCTL_MAGIC, 1)
#define OPENFIBERS_IOCTL_CREATE_FIBER _IOW(OPENFIBERS_IOCTL_MAGIC, 2, unsigned long)
#define OPENFIBERS_IOCTL_SWITCH_TO_FIBER _IOW(OPENFIBERS_IOCTL_MAGIC, 3, unsigned long)
#define OPENFIBERS_IOCTL_CONVERT_TO_FIBER _IO(OPENFIBERS_IOCTL_MAGIC, 4)
#define OPENFIBERS_IOCTL_FLS_ALLOC _IO(OPENFIBERS_IOCTL_MAGIC, 5)
#define OPENFIBERS_IOCTL_FLS_FREE _IOW(OPENFIBERS_IOCTL_MAGIC, 6, unsigned long)
#define OPENFIBERS_IOCTL_FLS_SET _IOW(OPENFIBERS_IOCTL_MAGIC, 7, unsigned long)
#define OPENFIBERS_IOCTL_FLS_GET _IOWR(OPENFIBERS_IOCTL_MAGIC, 8, unsigned long)
#define OPENFIBERS_DEVICE_FILE_NAME "/dev/openfibers"

//typedef pid_t fid_t;
struct fiber_request_t
{
    void (*start_address)(void *);
    void *start_args;
    void *stack_address;
    unsigned long stack_size;
};

struct fls_request_t
{
    long value;
    unsigned long idx;
};

#define STACK_DEFAULT_SIZE 8192

__thread int libfibers_local_file_desc;
#define NUM_FIBERS 30
//static void* fibers[NUM_FIBERS];

// Simplistic allocation for FLS
long libfibers_ioctl_fls_alloc(void)
{
    long res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_FLS_ALLOC);
    return res;
}

// Get a FLS value
long libfibers_ioctl_fls_get(long idx)
{
    struct fls_request_t request = {
        .idx = idx,
        .value = -1,
    };
    long res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_FLS_GET, (unsigned long)&request);
    if(res < 0)
        return -1;
    else
        return request.value;
}

// Dummy: we don't actually free FLS here...
bool libfibers_ioctl_fls_free(long idx)
{
    long res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_FLS_FREE, idx);
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
        //printf("libfibers ioctl ping failed");
        return;
    }
    //printf("libfibers ping done\n");
}

void* libfibers_ioctl_create_fiber(void (*addr)(void *), void* args)
{
    unsigned long size = STACK_DEFAULT_SIZE;
    struct fiber_request_t request = {
        .stack_address = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + size - 0x8,
        .start_address = addr,
        .stack_size = size,
        .start_args = args,
    };
    long res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_CREATE_FIBER, (unsigned long)&request);
    if (res < 0)
    {
        //printf("libfibers ioctl fiber create failed");
        return NULL;
    }
    //printf("libfibers fiber %d create done\n", res);
    return (void*) res;
}

void* libfibers_ioctl_switch_to_fiber(void* fid)
{
    unsigned char fpu_state[512] __attribute__((aligned(16))); // fxsave wants 16-byte aligned memory
    // tell gcc you will clobber them, so let him save and restore them for us during fiber switches
    asm volatile(
        "\n\t" ::
            : "%rbp", "%rbx", "%r12", "%r13", "%r14", "%r15");
    /*asm volatile(
        "lahf\n\t"
        "seto %%al\n\t"
        "mov %%rax, %0\n\t" ::
            : "%rax");*/
    asm volatile("fxsave %0": "+m"(fpu_state));
    //avoid libc calling other levels of functions
    //long res = syscall(SYS_ioctl, libfibers_local_file_desc, OPENFIBERS_IOCTL_SWITCH_TO_FIBER, fid);
    //long res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_SWITCH_TO_FIBER, fid);
    long res;
    asm volatile(
        "syscall"
        : "=a"(res)
        : "0"(SYS_ioctl), "D"(libfibers_local_file_desc), "S"(OPENFIBERS_IOCTL_SWITCH_TO_FIBER), "d"(fid)
        : "cc", "%rcx", "%r11", "memory");
    asm volatile("fxrstor %0": "+m"(fpu_state));
    /*asm volatile(
        //"pop %%rax\n\t"
        "pop %%rax\n\t"
        "add $0x7f, %%al\n\t"
        "sahf\n\t " ::
            : "%rax");*/
    if (res < 0)
    {
        return NULL;
    }
    return (void*)res;
}

void* libfibers_ioctl_convert_to_fiber(void)
{
    libfibers_local_file_desc = open(OPENFIBERS_DEVICE_FILE_NAME, 0);
    if (libfibers_local_file_desc < 0)
    {
        //printf("Can't open libfibers device file");
        return NULL;
    }

    long res = ioctl(libfibers_local_file_desc, OPENFIBERS_IOCTL_CONVERT_TO_FIBER);
    if (res < 0)
    {
        //printf("libfibers ioctl fiber conversion failed");
        return NULL;
    }
    //printf("libfibers fiber %d conversion done\n", res);
    return (void*) res;
}

/*
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
        //printf("tid %d in %d switching to %d\n", tid, fibers[(unsigned long)arg], fibers[f]);
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

    void* fid = libfibers_ioctl_convert_to_fiber();

    while (!init_complete)
        ;

    while (true)
    {
        f = get_random_fiber();
        //printf("WARNING thread %d: while switching to %d\n", tid, f);
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

    void* f = libfibers_ioctl_convert_to_fiber();

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
*/
