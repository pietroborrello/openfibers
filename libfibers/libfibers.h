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
#define OPENFIBERS_DEVICE_FILE_NAME "/dev/openfibers"

struct fiber_request_t
{
    unsigned long start_address;
    unsigned long start_parameters;
    unsigned long stack_address;
    unsigned long stack_size;
};

