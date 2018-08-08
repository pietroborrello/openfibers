#ifndef OPENFIBERS_IOCTL_H
#define OPENFIBERS_IOCTL_H

#include <linux/ioctl.h>

#define OPENFIBERS_IOCTL_MAGIC 'o'

#define OPENFIBERS_IOCTL_PING _IO(OPENFIBERS_IOCTL_MAGIC, 1)
#define OPENFIBERS_IOCTL_CREATE_FIBER _IOW(OPENFIBERS_IOCTL_MAGIC, 2, unsigned long)
#define OPENFIBERS_IOCTL_SWITCH_TO_FIBER _IOW(OPENFIBERS_IOCTL_MAGIC, 3, unsigned long)
#define OPENFIBERS_IOCTL_CONVERT_TO_FIBER _IO(OPENFIBERS_IOCTL_MAGIC, 4)
#define OPENFIBERS_IOCTL_FLS_ALLOC _IO(OPENFIBERS_IOCTL_MAGIC, 5)
#define OPENFIBERS_IOCTL_FLS_FREE _IO(OPENFIBERS_IOCTL_MAGIC, 6)
#define OPENFIBERS_IOCTL_FLS_SET _IO(OPENFIBERS_IOCTL_MAGIC, 7)
#define OPENFIBERS_IOCTL_FLS_GET _IO(OPENFIBERS_IOCTL_MAGIC, 8)

#endif

#include <linux/rbtree.h>
#include <linux/slab.h>

#ifndef FALSE
#define FALSE (1 == 0)
#endif
#ifndef TRUE
#define TRUE (1 == 1)
#endif

/// This structure is used to maintain execution context for LPs' userspace threads
typedef struct __exec_context_t
{
    // This is the space for general purpose registers
    unsigned long long rax;
    unsigned long long rdx;
    unsigned long long rcx;
    unsigned long long rbx;
    unsigned long long rsp;
    unsigned long long rbp;
    unsigned long long rsi;
    unsigned long long rdi;
    unsigned long long r8;
    unsigned long long r9;
    unsigned long long r10;
    unsigned long long r11;
    unsigned long long r12;
    unsigned long long r13;
    unsigned long long r14;
    unsigned long long r15;
    unsigned long long rip;
    unsigned long long flags;

    // Space for other registers
    unsigned char others[512] __attribute__((aligned(16))); // fxsave wants 16-byte aligned memory
} exec_context_t;

typedef pid_t fid_t;
typedef struct
{
    fid_t fid;
    volatile bool running;
    unsigned long start_address;
    exec_context_t context;
} fiber_t;

struct fibers_node
{
    struct rb_node node;
    fid_t fid;
    fiber_t fiber;
};

struct fibers_by_tgid_node
{
    struct rb_node node;
    pid_t tgid;
    fid_t max_fid;
    struct rb_root* fibers_root;
};

struct fiber_request_t
{
    unsigned long start_address;
    unsigned long start_parameters;
    unsigned long stack_address;
    unsigned long stack_size;
};