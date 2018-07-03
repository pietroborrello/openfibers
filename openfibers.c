#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>

#include "openfibers.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("pietroborrello");
MODULE_DESCRIPTION("User Level Thread back-end");

static int __init fibers_init(void)
{
    printk(KERN_ALERT "hello...\n");
}

module_init(fibers_init);
module_exit(fibers_cleanup);
