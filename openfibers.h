#ifndef OPENFIBERS_IOCTL_H
#define OPENFIBERS_IOCTL_H

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/device.h>  // Header to support the kernel Driver Model
#include <linux/kernel.h>  // Contains types, macros, functions for the kernel
#include <linux/fs.h>      // Header for the Linux file system support
#include <linux/uaccess.h> // Required for the copy to user function
#include <linux/kprobes.h> // Required for kprobe
#include <linux/proc_fs.h>
#include <asm/fpu/types.h>
#include <asm/fpu/internal.h>

#include <linux/ioctl.h>

#define OPENFIBERS_IOCTL_MAGIC 'o'

#define OPENFIBERS_IOCTL_PING _IO(OPENFIBERS_IOCTL_MAGIC, 1)
#define OPENFIBERS_IOCTL_CREATE_FIBER _IOW(OPENFIBERS_IOCTL_MAGIC, 2, unsigned long)
#define OPENFIBERS_IOCTL_SWITCH_TO_FIBER _IOW(OPENFIBERS_IOCTL_MAGIC, 3, unsigned long)
#define OPENFIBERS_IOCTL_CONVERT_TO_FIBER _IO(OPENFIBERS_IOCTL_MAGIC, 4)
#define OPENFIBERS_IOCTL_FLS_ALLOC _IO(OPENFIBERS_IOCTL_MAGIC, 5)
#define OPENFIBERS_IOCTL_FLS_FREE _IOW(OPENFIBERS_IOCTL_MAGIC, 6, unsigned long)
#define OPENFIBERS_IOCTL_FLS_SET _IOW(OPENFIBERS_IOCTL_MAGIC, 7, unsigned long)
#define OPENFIBERS_IOCTL_FLS_GET _IOWR(OPENFIBERS_IOCTL_MAGIC, 8, unsigned long)

#endif

#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/atomic.h>

#ifndef FALSE
#define FALSE (1 == 0)
#endif
#ifndef TRUE
#define TRUE (1 == 1)
#endif

#define MAX_FLS 4096

/// This structure is used to maintain execution context for LPs' userspace threads
typedef struct __exec_context_t
{
    // This is the space for general purpose registers
    unsigned long long orig_rax;
    unsigned long long rax;
    unsigned long long rdx;
    unsigned long long rcx;
    //unsigned long long rbx;
    unsigned long long rsp;
    //unsigned long long rbp;
    unsigned long long rsi;
    unsigned long long rdi;
    unsigned long long r8;
    unsigned long long r9;
    unsigned long long r10;
    unsigned long long r11;
    //unsigned long long r12;
    //unsigned long long r13;
    //unsigned long long r14;
    //unsigned long long r15;
    unsigned long long rip;
    unsigned long long flags;

    // Space for other registers

    //unsigned char others[512] __attribute__((aligned(16))); // fxsave wants 16-byte aligned memory
    struct fpu fpu_context;
} exec_context_t;

typedef pid_t fid_t;
typedef struct
{
    fid_t fid;
    atomic_t running;
    void (*start_address)(void *);
    exec_context_t context;
    unsigned long idx;
    unsigned long fls[4096];
    unsigned long fls_idx;
    struct proc_dir_entry *proc_entry;
} fiber_t;

struct fibers_node
{
    struct rb_node node;
    fid_t fid;
    fiber_t fiber;
    struct fibers_by_tgid_node* fibers_root_node;
};

struct fibers_by_tgid_node
{
    struct rb_node node;
    pid_t tgid;
    struct rb_root *fibers_root;
    struct rw_semaphore fibers_root_rwsem;
    struct kref refcount;
    atomic_t max_fid;
    struct proc_dir_entry *tgid_proc_fibers;
};

struct fiber_request_t
{
    void (*start_address)(void *);
    void* start_args;
    void* stack_address;
    unsigned long stack_size;
};

struct fls_request_t
{
    long value;
    unsigned long idx;
};