#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/device.h>     // Header to support the kernel Driver Model
#include <linux/kernel.h>     // Contains types, macros, functions for the kernel
#include <linux/fs.h>         // Header for the Linux file system support
#include <linux/uaccess.h>    // Required for the copy to user function
#include <linux/kprobes.h>    // Required for kprobe

#define DEVICE_NAME "openfibers" ///< The device will appear at /dev/... using this value
#define CLASS_NAME "openfibers"      ///< The device class -- this is a character device driver

#include "openfibers.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("pietroborrello");
MODULE_DESCRIPTION("openfibers: User Level Threads management module");


struct rb_root fibers_by_tgid_tree = RB_ROOT; // mantains fibers by tgid
static /* TODO: __thread - Unknown symbol _GLOBAL_OFFSET_TABLE_ (err 0)*/ fiber_t *current_fiber = NULL; // to know which fiber unset running

static int majorNumber;                     ///< Stores the device number -- determined automatically

static struct class *openfibersClass = NULL;   ///< The device-driver class struct pointer
static struct device *openfibersDevice = NULL; ///< The device-driver device struct pointer

// The prototype functions for the character driver -- must come before the struct definition
static int openfibers_dev_open(struct inode *, struct file *);
static int openfibers_dev_release(struct inode *, struct file *);
static ssize_t openfibers_dev_read(struct file *, char *, size_t, loff_t *);
static long openfibers_dev_ioctl(struct file *, unsigned int, unsigned long);

// kprobe handler
static struct kprobe kp;


struct fibers_by_tgid_node *tgid_rbtree_search(struct rb_root *root, pid_t tgid)
{
    struct rb_node *node = root->rb_node;

    while (node)
    {
        struct fibers_by_tgid_node *data = container_of(node, struct fibers_by_tgid_node, node);
        int result;

        result = tgid - data->tgid;

        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return data;
    }
    return NULL;
}

struct fibers_node *fid_rbtree_search(struct rb_root *root, fid_t fid)
{
    struct rb_node *node = root->rb_node;

    while (node)
    {
        struct fibers_node *data = container_of(node, struct fibers_node, node);
        int result;

        result = fid - data->fid;

        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return data;
    }
    return NULL;
}

int tgid_rbtree_insert(struct rb_root *root, struct fibers_by_tgid_node *data)
{
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    /* Figure out where to put new node */
    while (*new)
    {
        struct fibers_by_tgid_node *this = container_of(*new, struct fibers_by_tgid_node, node);
        int result = data->tgid - this->tgid;
        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else
            return FALSE;
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    return TRUE;
}

int fid_rbtree_insert(struct rb_root *root, struct fibers_node *data)
{
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    /* Figure out where to put new node */
    while (*new)
    {
        struct fibers_node *this = container_of(*new, struct fibers_node, node);
        int result = data->fid - this->fid;
        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else
            return FALSE;
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);

    return TRUE;
}

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
    //pr_info("Device has been opened\n");
    return 0;
}

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int openfibers_dev_release(struct inode *inodep, struct file *filep)
{
    //pr_info("Device successfully closed\n");
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

static struct fibers_by_tgid_node* initialize_fibers_for_current(void)
{
    int ret;
    struct fibers_by_tgid_node *data;

    pr_info("initializing fibers for: %d\n", current->tgid);

    data = kmalloc(sizeof(struct fibers_by_tgid_node), GFP_KERNEL);
    if(!data)
    {
        pr_crit("memory allocation failed\n");
        return ERR_PTR(-ENOMEM);
    }
    data->tgid = current->tgid;
    data->max_fid = 0;
    // allocate the root for fibers for current process when inserting new node by tgid
    data->fibers_root = kmalloc(sizeof(struct rb_root), GFP_KERNEL | __GFP_ZERO);
    if (!data->fibers_root)
        return FALSE;

    // start with empty tree
    data->fibers_root->rb_node = NULL;

    ret = tgid_rbtree_insert(&fibers_by_tgid_tree, data);
    if (!ret)
        {
            pr_crit("insertion in fibers by tgid failed\n");
            return ERR_PTR(-EEXIST);
        }

    return data;
}

// create a new fiber
static long openfibers_ioctl_create_fiber(unsigned long stack_address, unsigned long start_address, unsigned long parameter)
{
    struct fibers_by_tgid_node *tgid_data;
    struct fibers_node *fiber_data;
    struct pt_regs *regs;
    tgid_data = tgid_rbtree_search(&fibers_by_tgid_tree, current->tgid);
    if (!tgid_data)
    {
        tgid_data = initialize_fibers_for_current();
        if (IS_ERR(tgid_data))
        {
            pr_crit("failed fibers initialization for tgid: %d\n", current->tgid);
            return PTR_ERR(tgid_data);
        }
    }
    fiber_data = kmalloc(sizeof(struct fibers_node), GFP_KERNEL | __GFP_ZERO);
    if (!fiber_data)
        return -ENOMEM;
    fiber_data->fid = tgid_data->max_fid++;
    fiber_data->fiber.fid = fiber_data->fid;
    fiber_data->fiber.running = FALSE;
    fiber_data->fiber.start_address = start_address;
    if(!fid_rbtree_insert(tgid_data->fibers_root, fiber_data))
        return -ENOMEM;

    // HANDLE CREATION
    regs = task_pt_regs(current);

    fiber_data->fiber.context.rsp = stack_address;
    fiber_data->fiber.context.rip = start_address;
    
    return fiber_data->fid;
}

// convert to fiber
static long openfibers_ioctl_convert_to_fiber(void)
{
    struct fibers_by_tgid_node *tgid_data;
    struct fibers_node *new_fiber_data;
    fid_t fid;
    //struct pt_regs *regs = task_pt_regs(current);

    long res = openfibers_ioctl_create_fiber(0, 0, 0);
    if(res < 0)
        return res;
    fid = res;

    tgid_data = tgid_rbtree_search(&fibers_by_tgid_tree, current->tgid);
    if (!tgid_data)
    {
        pr_crit("Thread %d conversion to fiber failed\n", current->tgid);
        return -ENOMEM;
    }
    new_fiber_data = fid_rbtree_search(tgid_data->fibers_root, fid);
    if (!new_fiber_data)
    {
        pr_crit("Thread %d conversion to fiber failed\n", current->tgid);
        return -ENOMEM;
    }
    current_fiber = &new_fiber_data->fiber;
    return new_fiber_data->fid;
}

// switch to a new fiber
static long openfibers_ioctl_switch_to_fiber(fid_t to_fiber)
{
    struct fibers_by_tgid_node *tgid_data;
    struct fibers_node *to_fiber_data;
    struct pt_regs *regs;

    tgid_data = tgid_rbtree_search(&fibers_by_tgid_tree, current->tgid);
    if (!tgid_data || !current_fiber)
    {
        pr_crit("Process %d has no fiber context initialized\n", current->tgid);
        return -ENOENT;
    }
    to_fiber_data = fid_rbtree_search(tgid_data->fibers_root, to_fiber);
    if (!to_fiber_data)
    {
        pr_crit("Process %d has no fiber with id %u\n", current->tgid, to_fiber);
        return -ENOENT;
    }
    pr_info("Process %d switching from fiber %u to fiber %u\n", current->tgid, current_fiber->fid, to_fiber);

    // HANDLE SWITCH
    regs = task_pt_regs(current);

    current_fiber->context.rsp = regs->sp;
    current_fiber->context.rbp = regs->bp;
    current_fiber->context.rax = regs->ax;
    current_fiber->context.rbx = regs->bx;
    current_fiber->context.rcx = regs->cx;
    current_fiber->context.rdx = regs->dx;
    current_fiber->context.rdi = regs->di;
    current_fiber->context.rsi = regs->si;

    current_fiber->context.rip = regs->ip;
    pr_crit("Old stack: 0x%016llx - Old IP: 0x%016llx\n", (long long unsigned int)regs->sp, (long long unsigned int)regs->ip);

    regs->sp = to_fiber_data->fiber.context.rsp;
    regs->bp = to_fiber_data->fiber.context.rbp;
    regs->ip = to_fiber_data->fiber.context.rip;

    current_fiber = &to_fiber_data->fiber;

    pr_crit("New stack: 0x%016llx - New IP: 0x%016llx \n", (long long unsigned int)regs->sp, (long long unsigned int)regs->ip);

    return to_fiber_data->fid;
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
    {
        struct fibers_by_tgid_node *data;
        struct rb_node *node;
        data = tgid_rbtree_search(&fibers_by_tgid_tree, current->tgid);
        if (!data){
            data = initialize_fibers_for_current();
            if (IS_ERR(data))
            {
                pr_crit("failed fibers initialization for tgid: %d\n", current->tgid);
                return PTR_ERR(data);
            }
        }
        for (node = rb_first(data->fibers_root); node; node = rb_next(node))
            pr_info("fid=%d start=%lu\n", rb_entry(node, struct fibers_node, node)->fid, rb_entry(node, struct fibers_node, node)->fiber.start_address);
    }
        break;
    case OPENFIBERS_IOCTL_CREATE_FIBER:
        return openfibers_ioctl_create_fiber(((struct fiber_request_t*) arg)->stack_address, ((struct fiber_request_t*)arg)->start_address, 0);
        break;
    case OPENFIBERS_IOCTL_SWITCH_TO_FIBER:
        return openfibers_ioctl_switch_to_fiber((fid_t) arg);
        break;
    case OPENFIBERS_IOCTL_CONVERT_TO_FIBER:
        return openfibers_ioctl_convert_to_fiber();
        break;
    case OPENFIBERS_IOCTL_FLS_ALLOC:
        break;
    case OPENFIBERS_IOCTL_FLS_FREE:
        break;
    case OPENFIBERS_IOCTL_FLS_GET:
        break;
    case OPENFIBERS_IOCTL_FLS_SET:
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

static void fibers_tree_cleanup(struct rb_root *root)
{
    struct rb_node *next = rb_first_postorder(root);

    // postorder visit to free all tree
    while (next)
    {
        struct fibers_node *this = container_of(next, struct fibers_node, node);
        next = rb_next_postorder(next);

        rb_erase(&this->node, root);
        //kfree(this->fiber);
        // TODO: free process stack!
        kfree(this);
    }
}

static void tgid_fibers_tree_cleanup(struct rb_root *root)
{
    struct rb_node *next = rb_first_postorder(root);

    // postorder visit to free all tree
    while (next)
    {
        struct fibers_by_tgid_node *this = container_of(next, struct fibers_by_tgid_node, node);
        next = rb_next_postorder(next);

        rb_erase(&this->node, root);
        fibers_tree_cleanup(this->fibers_root);
        kfree(this->fibers_root);
        kfree(this);
    }
}

// kprobe called function
static int handle_kprobe(struct kprobe *kp, struct pt_regs *regs)
{
    //pr_info("exiting: %d\n", current->pid);
    struct fibers_by_tgid_node *data = tgid_rbtree_search(&fibers_by_tgid_tree, current->tgid);

    if (data){
        pr_info("cleanup: %d\n", data->tgid);
        rb_erase(&data->node, &fibers_by_tgid_tree);
        fibers_tree_cleanup(data->fibers_root);
        kfree(data->fibers_root);
        kfree(data);
    }

    return 0;
}

/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */
static int __init fibers_init(void)
{
    int ret;

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

    // register the kprobe
    kp.pre_handler = handle_kprobe;
    kp.symbol_name = "do_group_exit";
    ret = register_kprobe(&kp);
    if (ret < 0)
    {
        pr_crit("Failed to set kprobe\n");
        return ret;
    }

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
    unregister_kprobe(&kp);                              // remove kprobe

    // cleanup all the fibers pending
    tgid_fibers_tree_cleanup(&fibers_by_tgid_tree);

    pr_info("cleanup done\n");
    return;
}

module_init(fibers_init);
module_exit(fibers_cleanup);
