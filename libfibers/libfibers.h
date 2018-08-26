#include <linux/ioctl.h>

#define OPENFIBERS_IOCTL_MAGIC 'o'

#define OPENFIBERS_IOCTL_PING _IO(OPENFIBERS_IOCTL_MAGIC, 1)
#define OPENFIBERS_IOCTL_CREATE_FIBER _IOW(OPENFIBERS_IOCTL_MAGIC, 2, unsigned long)
#define OPENFIBERS_IOCTL_SWITCH_TO_FIBER _IOW(OPENFIBERS_IOCTL_MAGIC, 3, unsigned long)
#define OPENFIBERS_IOCTL_CONVERT_TO_FIBER _IO(OPENFIBERS_IOCTL_MAGIC, 4)
#define OPENFIBERS_IOCTL_FLS_ALLOC _IO(OPENFIBERS_IOCTL_MAGIC, 5)
#define OPENFIBERS_IOCTL_FLS_FREE _IOW(OPENFIBERS_IOCTL_MAGIC, 6, unsigned long)
#define OPENFIBERS_IOCTL_FLS_SET _IOW(OPENFIBERS_IOCTL_MAGIC, 7, unsigned long)
#define OPENFIBERS_IOCTL_FLS_GET _IOW(OPENFIBERS_IOCTL_MAGIC, 8, unsigned long)
#define OPENFIBERS_DEVICE_FILE_NAME "/dev/openfibers"

typedef pid_t fid_t;
struct fiber_request_t
{
    void (*start_address)(void *);
    void *start_args;
    void *stack_address;
    unsigned long stack_size;
};

