#ifndef OPENFIBERS_IOCTL_H
#define OPENFIBERS_IOCTL_H

#include <linux/ioctl.h>

#define OPENFIBERS_IOCTL_MAGIC 'o'

#define OPENFIBERS_IOCTL_PING _IO(OPENFIBERS_IOCTL_MAGIC, 1)
#define OPENFIBERS_IOCTL_CREATE_FIBER _IO(OPENFIBERS_IOCTL_MAGIC, 2)
#define OPENFIBERS_IOCTL_SWITCH_TO_FIBER _IO(OPENFIBERS_IOCTL_MAGIC, 3)
#define OPENFIBERS_IOCTL_FLS_ALLOC _IO(OPENFIBERS_IOCTL_MAGIC, 4)
#define OPENFIBERS_IOCTL_FLS_FREE _IO(OPENFIBERS_IOCTL_MAGIC, 5)
#define OPENFIBERS_IOCTL_FLS_SET _IO(OPENFIBERS_IOCTL_MAGIC, 6)
#define OPENFIBERS_IOCTL_FLS_GET _IO(OPENFIBERS_IOCTL_MAGIC, 7)

#endif

#include <linux/rbtree.h>
#include <linux/slab.h>

#ifndef FALSE
#define FALSE (1 == 0)
#endif
#ifndef TRUE
#define TRUE (1 == 1)
#endif

typedef pid_t fid_t;
typedef struct
{
    volatile bool running;
} fiber_t;

struct fibers_node
{
    struct rb_node node;
    fid_t fid;
    fiber_t *fiber;
};

struct fibers_by_tgid_node
{
    struct rb_node node;
    pid_t tgid;
    struct rb_root* fibers_root;
};