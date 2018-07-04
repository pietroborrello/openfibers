#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/device.h>     // Header to support the kernel Driver Model
#include <linux/kernel.h>     // Contains types, macros, functions for the kernel
#include <linux/fs.h>         // Header for the Linux file system support
#include <linux/uaccess.h>    // Required for the copy to user function

#define DEVICE_NAME "openfibers" ///< The device will appear at /dev/... using this value
#define CLASS_NAME "openfibers"      ///< The device class -- this is a character device driver

#include "openfibers.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("pietroborrello");
MODULE_DESCRIPTION("openfibers: User Level Threads management module");


static int majorNumber;                     ///< Stores the device number -- determined automatically

static struct class *openfibersClass = NULL;   ///< The device-driver class struct pointer
static struct device *openfibersDevice = NULL; ///< The device-driver device struct pointer

// The prototype functions for the character driver -- must come before the struct definition
static int openfibers_dev_open(struct inode *, struct file *);
static int openfibers_dev_release(struct inode *, struct file *);
static ssize_t openfibers_dev_read(struct file *, char *, size_t, loff_t *);
static long openfibers_dev_ioctl(struct file *, unsigned int, unsigned long);

/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
 *  /linux/fs.h lists the callback functions that you wish to associated with your file operations
 *  using a C99 syntax structure. char devices usually implement open, read, write and release calls
 */
static struct file_operations dev_fops =
{
    .owner = THIS_MODULE,
    .open = openfibers_dev_open,
    .read = openfibers_dev_read,
    .unlocked_ioctl = openfibers_dev_ioctl,
    .release = openfibers_dev_release,
};

/** @brief The device open function that is called each time the device is opened
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int openfibers_dev_open(struct inode *inodep, struct file *filep)
{
    pr_info("Device has been opened\n");
    return 0;
}

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int openfibers_dev_release(struct inode *inodep, struct file *filep)
{
    pr_info("Device successfully closed\n");
    return 0;
}

/** @brief This function is called whenever device is being read from user space i.e. data is
 *  being sent from the device to the user. In this case is uses the copy_to_user() function to
 *  send the buffer string to the user and captures any errors.
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 *  @param buffer The pointer to the buffer to which this function writes the data
 *  @param len The length of the b
 *  @param offset The offset if required
 */
static ssize_t openfibers_dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    pr_info("Device read\n");
    return 0;
}

/** @brief * This function is called whenever a process tries to do an ioctl on our
 *  device file.
 *  @param f A pointer to a file object (defined in linux/fs.h)
 *  @param cmd The command
 *  @param arg The arguments
 */
static long openfibers_dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    switch (cmd)
    {
    case OPENFIBERS_IOCTL_PING:
        pr_info("ping");
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

// modify permissions
static char *openfibers_devnode(struct device *dev, umode_t *mode)
{
    if (mode)
        *mode = 0644;
    return NULL; 
}

/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */
static int __init fibers_init(void)
{
    // Try to dynamically allocate a major number for the device -- more difficult but worth it
    majorNumber = register_chrdev(0, DEVICE_NAME, &dev_fops);
    if (majorNumber < 0)
    {
        pr_crit("failed to register a major number\n");
        return majorNumber;
    }

    // Register the device class
    openfibersClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(openfibersClass))
    { // Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        pr_crit("Failed to register device class\n");
        return PTR_ERR(openfibersClass); // Correct way to return an error on a pointer
    }
    openfibersClass->devnode = openfibers_devnode;

    // Register the device driver
    openfibersDevice = device_create(openfibersClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(openfibersDevice))
    {                                // Clean up if there is an error
        class_destroy(openfibersClass);
        unregister_chrdev(majorNumber, DEVICE_NAME);
        pr_crit("Failed to create the device\n");
        return PTR_ERR(openfibersDevice);
    }

    pr_info("registered correctly with major number %d\n", majorNumber);
    return 0;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit fibers_cleanup(void)
{
    device_destroy(openfibersClass, MKDEV(majorNumber, 0)); // remove the device
    class_unregister(openfibersClass);                      // unregister the device class
    class_destroy(openfibersClass);                         // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);         // unregister the major number
    pr_info("cleanup done\n");
    return;
}

module_init(fibers_init);
module_exit(fibers_cleanup);
