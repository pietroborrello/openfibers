#ifndef OPENFIBERS_IOCTL_H
#define OPENFIBERS_IOCTL_H

#include <linux/ioctl.h>

#define OPENFIBERS_IOCTL_MAGIC 'o'

#define OPENFIBERS_IOCTL_PING _IO(OPENFIBERS_IOCTL_MAGIC, 1)

#endif