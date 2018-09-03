#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define DEVICE_NAME "openfibers" ///< The device will appear at /dev/... using this value
#define CLASS_NAME "openfibers"      ///< The device class -- this is a character device driver

#include "openfibers.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("pietroborrello");
MODULE_DESCRIPTION("openfibers: User Level Threads management module");


static struct rb_root fibers_by_tgid_tree = RB_ROOT; // mantains fibers by tgid
//static /* TODO: __thread - Unknown symbol _GLOBAL_OFFSET_TABLE_ (err 0)*/ fiber_t *current_fiber = NULL; // to know which fiber unset running
static rwlock_t fibers_by_tgid_tree_rwlock = __RW_LOCK_UNLOCKED(fibers_by_tgid_tree_rwlock);
static DEFINE_SPINLOCK(initialization_lock);

static int majorNumber;                     ///< Stores the device number -- determined automatically

static struct class *openfibersClass = NULL;   ///< The device-driver class struct pointer
static struct device *openfibersDevice = NULL; ///< The device-driver device struct pointer

// The prototype functions for the character driver -- must come before the struct definition
static int openfibers_dev_open(struct inode *, struct file *);
static int openfibers_dev_release(struct inode *, struct file *);
static ssize_t openfibers_dev_read(struct file *, char *, size_t, loff_t *);
static long openfibers_dev_ioctl(struct file *, unsigned int, unsigned long);


static struct fibers_by_tgid_node *tgid_rbtree_search(struct rb_root *root, pid_t tgid)
{
    struct rb_node *node;
    unsigned long fibers_by_tgid_tree_rwlock_flags;
    read_lock_irqsave(&fibers_by_tgid_tree_rwlock, fibers_by_tgid_tree_rwlock_flags);
    node = root->rb_node;

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
            {
                read_unlock_irqrestore(&fibers_by_tgid_tree_rwlock, fibers_by_tgid_tree_rwlock_flags);
                return data;
            }
    }
    read_unlock_irqrestore(&fibers_by_tgid_tree_rwlock, fibers_by_tgid_tree_rwlock_flags);
    return NULL;
}

static struct fibers_node *fid_rbtree_search(struct rb_root *root, fid_t fid, rwlock_t fibers_root_rwlock)
{
    struct rb_node *node;
    unsigned long fibers_root_rwlock_flags;
    read_lock_irqsave(&fibers_root_rwlock, fibers_root_rwlock_flags);
    node = root->rb_node;

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
        {
            read_unlock_irqrestore(&fibers_root_rwlock, fibers_root_rwlock_flags);
            return data;
        }
    }
    read_unlock_irqrestore(&fibers_root_rwlock, fibers_root_rwlock_flags);
    return NULL;
}

static int tgid_rbtree_insert(struct rb_root *root, struct fibers_by_tgid_node *data)
{
    struct rb_node **new, *parent;
    unsigned long fibers_by_tgid_tree_rwlock_flags;
    write_lock_irqsave(&fibers_by_tgid_tree_rwlock, fibers_by_tgid_tree_rwlock_flags);
    new = &(root->rb_node);
    parent = NULL;

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
            {
            write_unlock_irqrestore(&fibers_by_tgid_tree_rwlock, fibers_by_tgid_tree_rwlock_flags);
            return FALSE;
            }
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    write_unlock_irqrestore(&fibers_by_tgid_tree_rwlock, fibers_by_tgid_tree_rwlock_flags);
    return TRUE;
}

static int fid_rbtree_insert(struct rb_root *root, struct fibers_node *data, rwlock_t fibers_root_rwlock)
{
    struct rb_node **new, *parent;
    unsigned long fibers_root_rwlock_flags;
    write_lock_irqsave(&fibers_root_rwlock, fibers_root_rwlock_flags);
    new = &(root->rb_node);
    parent = NULL;

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
        {
            write_unlock_irqrestore(&fibers_root_rwlock, fibers_root_rwlock_flags);
            return FALSE;
        }
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    write_unlock_irqrestore(&fibers_root_rwlock, fibers_root_rwlock_flags);
    return TRUE;
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
    struct rb_node *next;
    unsigned long fibers_by_tgid_tree_rwlock_flags;
    //only to be sure, should not be any fiber active or present
    write_lock_irqsave(&fibers_by_tgid_tree_rwlock, fibers_by_tgid_tree_rwlock_flags);
    next = rb_first_postorder(root);

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
    write_unlock_irqrestore(&fibers_by_tgid_tree_rwlock, fibers_by_tgid_tree_rwlock_flags);
    // TODO: handle deletion, not to block others
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
static struct fibers_by_tgid_node* initialize_fibers_for_current(void);
/** @brief The device open function that is called each time the device is opened
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int openfibers_dev_open(struct inode *inodep, struct file *filep)
{
    struct fibers_by_tgid_node *tgid_data;
    unsigned long flags;

    spin_lock_irqsave(&initialization_lock, flags);
    tgid_data = initialize_fibers_for_current();

    if (IS_ERR(tgid_data) && PTR_ERR(tgid_data) == -EEXIST)
    {
        tgid_data = tgid_rbtree_search(&fibers_by_tgid_tree, current->tgid);
        if(!tgid_data)
        {
            pr_crit("failed fibers initialization for pid %d, should exist\n", current->pid);
            spin_unlock_irqrestore(&initialization_lock, flags);
            return -ENOENT;
        }
        kref_get(&tgid_data->refcount);
    }
    else if (IS_ERR(tgid_data))
    {
        pr_crit("failed fibers initialization for pid %d\n", current->pid);
        spin_unlock_irqrestore(&initialization_lock, flags);
        return PTR_ERR(tgid_data);
    }
    spin_unlock_irqrestore(&initialization_lock, flags);
    return 0;
}

static void release_tgid_entry(struct kref *ref)
{
    unsigned long fibers_root_rwlock_flags;
    unsigned long fibers_by_tgid_tree_rwlock_flags;
    struct fibers_by_tgid_node *data = container_of(ref, struct fibers_by_tgid_node, refcount);

    write_lock_irqsave(&fibers_by_tgid_tree_rwlock, fibers_by_tgid_tree_rwlock_flags);
    write_lock_irqsave(&data->fibers_root_rwlock, fibers_root_rwlock_flags);
    // // TODO: when lock and unlock?
    pr_info("cleanup: %d\n", data->tgid);
    rb_erase(&data->node, &fibers_by_tgid_tree);
    fibers_tree_cleanup(data->fibers_root);
    kfree(data->fibers_root);
    write_unlock_irqrestore(&data->fibers_root_rwlock, fibers_root_rwlock_flags);
    write_unlock_irqrestore(&fibers_by_tgid_tree_rwlock, fibers_by_tgid_tree_rwlock_flags);
    kfree(data);
}

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int openfibers_dev_release(struct inode *inodep, struct file *filep)
{
    struct fibers_by_tgid_node *data;
    unsigned long flags;

    spin_lock_irqsave(&initialization_lock, flags);
    data = tgid_rbtree_search(&fibers_by_tgid_tree, current->tgid);

    if (!data)
    {
        pr_crit("failed fibers cleanup for pid %d, should exist\n", current->pid);
        spin_unlock_irqrestore(&initialization_lock, flags);
        return -ENOENT;
    }

    kref_put(&data->refcount, release_tgid_entry);
    spin_unlock_irqrestore(&initialization_lock, flags);
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
    atomic_t tmp = ATOMIC_INIT(0);

    pr_info("initializing fibers for: %d\n", current->pid);

    data = kmalloc(sizeof(struct fibers_by_tgid_node), GFP_KERNEL);
    if(!data)
    {
        pr_crit("memory allocation failed\n");
        return ERR_PTR(-ENOMEM);
    }
    data->tgid = current->tgid;
    data->max_fid = tmp;
    // allocate the root for fibers for current process when inserting new node by tgid
    data->fibers_root = kmalloc(sizeof(struct rb_root), GFP_KERNEL | __GFP_ZERO);
    if (!data->fibers_root)
    {
        pr_crit("memory allocation failed\n");
        kfree(data);
        return ERR_PTR(-ENOMEM);
    }

    // start with empty unlocked tree
    *data->fibers_root = RB_ROOT;
    rwlock_init(&data->fibers_root_rwlock);
    kref_init(&data->refcount);

    ret = tgid_rbtree_insert(&fibers_by_tgid_tree, data);
    if (!ret)
        {
            pr_info("tgid already inserted in fibers_by_tgid\n");
            kfree(data->fibers_root);
            kfree(data);
            return ERR_PTR(-EEXIST);
        }

    return data;
}

// create a new fiber
static long openfibers_ioctl_create_fiber(void *stack_address, void (*start_address)(void *), void *args, unsigned int is_running)
{
    struct fibers_by_tgid_node *tgid_data;
    struct fibers_node *fiber_data;

    // also get ref_count if creating a running fiber
    // need to wrap in read lock to avoid deletion until got ref_count
    tgid_data = tgid_rbtree_search(&fibers_by_tgid_tree, current->tgid);
    if (!tgid_data)
    {
        pr_crit("Thread %d has no fiber context initialized", current->pid);
        return -ENOENT;
    }
    fiber_data = kmalloc(sizeof(struct fibers_node), GFP_KERNEL | __GFP_ZERO);
    if (!fiber_data)
        return -ENOMEM;
    fiber_data->fid = atomic_inc_return(&tgid_data->max_fid);
    fiber_data->fibers_root_node = tgid_data;
    fiber_data->fiber.fid = fiber_data->fid;
    atomic_set(&fiber_data->fiber.running, is_running);
    fiber_data->fiber.start_address = start_address;
    fiber_data->fiber.fls_idx = 0;

    memset(&fiber_data->fiber.context, 0, sizeof(exec_context_t));
    fiber_data->fiber.context.rsp = (unsigned long)stack_address;
    fiber_data->fiber.context.rip = (unsigned long)start_address;
    fiber_data->fiber.context.rdi = (unsigned long)args;

    if (!fid_rbtree_insert(tgid_data->fibers_root, fiber_data, tgid_data->fibers_root_rwlock))
        return -ENOMEM;

    return fiber_data->fid;
}

// convert to fiber
static long openfibers_ioctl_convert_to_fiber(struct file *f)
{
    struct fibers_by_tgid_node *tgid_data;
    struct fibers_node *new_fiber_data;
    unsigned long fibers_root_rwlock_flags;
    struct rb_node *node;
    struct rb_node *tgid_node;
    fid_t fid;
    //struct pt_regs *regs = task_pt_regs(current);

    long res = openfibers_ioctl_create_fiber(0, 0, 0, 1);
    if(res < 0)
        return res;
    fid = res;

    tgid_data = tgid_rbtree_search(&fibers_by_tgid_tree, current->tgid);
    if (!tgid_data)
    {
        pr_crit("Thread %d unable to initialize fiber context\n", current->pid);
        return -ENOMEM;
    }

    new_fiber_data = fid_rbtree_search(tgid_data->fibers_root, fid, tgid_data->fibers_root_rwlock);
    if (!new_fiber_data)
    {
        pr_crit("Thread %d unable to convert to fiber %d\n", current->pid, fid);
        read_lock_irqsave(&tgid_data->fibers_root_rwlock, fibers_root_rwlock_flags);

        for (tgid_node = rb_first(&fibers_by_tgid_tree); tgid_node; tgid_node = rb_next(tgid_node))
            for (node = rb_first(tgid_data->fibers_root); node; node = rb_next(node))
                pr_info("tgid=%d fid=%d start=0x%lx\n", rb_entry(tgid_node, struct fibers_by_tgid_node, node)->tgid, rb_entry(node, struct fibers_node, node)->fid, (long unsigned int)rb_entry(node, struct fibers_node, node)->fiber.start_address);

        read_unlock_irqrestore(&tgid_data->fibers_root_rwlock, fibers_root_rwlock_flags);

        return -ENOMEM;
    }
    f->private_data = (void*) &new_fiber_data->fiber; // save current fiber for the thread
    return new_fiber_data->fid;
}

// switch to a new fiber
static long openfibers_ioctl_switch_to_fiber(struct file *f, fid_t to_fiber)
{
    struct fibers_by_tgid_node *tgid_data;
    struct fibers_node *to_fiber_data;
    struct pt_regs *regs;
    fiber_t *current_fiber = (fiber_t*) f->private_data;

    if (!current_fiber)
    {
        pr_crit("Thread %d has no current fiber context initialized\n", current->pid);
        return -ENOENT;
    }
    tgid_data = container_of(current_fiber, struct fibers_node, fiber)->fibers_root_node;
    to_fiber_data = fid_rbtree_search(tgid_data->fibers_root, to_fiber, tgid_data->fibers_root_rwlock);
    if (!to_fiber_data)
    {
        pr_crit("Thread %d has no fiber with id %u\n", current->pid, to_fiber);
        return -ENOENT;
    }

    
    if (atomic_cmpxchg(&to_fiber_data->fiber.running, 0, 1)) // not succeded
    {
        pr_info("Thread %d switching failed from fiber %u to fiber %u\n", current->pid, current_fiber->fid, to_fiber);
        return -EBUSY;
    }

    pr_info("Thread %d switching from fiber %u to fiber %u\n", current->pid, current_fiber->fid, to_fiber);

    // HANDLE SWITCH
    regs = task_pt_regs(current);

    current_fiber->context.rsp = regs->sp;
    //current_fiber->context.rbp = regs->bp;
    current_fiber->context.orig_rax = regs->orig_ax;
    current_fiber->context.rax = regs->ax;
    //current_fiber->context.rbx = regs->bx;
    current_fiber->context.rcx = regs->cx;
    current_fiber->context.rdx = regs->dx;
    current_fiber->context.rdi = regs->di;
    current_fiber->context.rsi = regs->si;
    current_fiber->context.r8 = regs->r8;
    current_fiber->context.r9 = regs->r9;
    current_fiber->context.r10 = regs->r10;
    current_fiber->context.r11 = regs->r11;
    //current_fiber->context.r12 = regs->r12;
    //current_fiber->context.r13 = regs->r13;
    //current_fiber->context.r14 = regs->r14;
    //current_fiber->context.r15 = regs->r15;
    current_fiber->context.flags = regs->flags;
    current_fiber->context.rip = regs->ip;
    //asm volatile("fxsave %0": "+m"(current_fiber->context.others));

    // Unknown symbol fpu__copy (err 0)
    //fpu__save(&current->thread.fpu);
    //fpu__copy(&current_fiber->context.fpu_context, &current->thread.fpu);
    fpu__save(&current_fiber->context.fpu_context);

    //pr_info("Thread %d - Old stack: 0x%llx - Old IP: 0x%llx\n", current->pid, (long long unsigned int)regs->sp, (long long unsigned int)regs->ip);

    regs->sp = to_fiber_data->fiber.context.rsp;
    //regs->bp = to_fiber_data->fiber.context.rbp;
    regs->orig_ax = to_fiber_data->fiber.context.orig_rax;
    regs->ax = to_fiber_data->fiber.context.rax;
    //regs->bx = to_fiber_data->fiber.context.rbx;
    regs->cx = to_fiber_data->fiber.context.rcx;
    regs->dx = to_fiber_data->fiber.context.rdx;
    regs->di = to_fiber_data->fiber.context.rdi;
    regs->si = to_fiber_data->fiber.context.rsi;
    regs->r8 = to_fiber_data->fiber.context.r8;
    regs->r9 = to_fiber_data->fiber.context.r9;
    regs->r10 = to_fiber_data->fiber.context.r10;
    regs->r11 = to_fiber_data->fiber.context.r11;
    //regs->r12 = to_fiber_data->fiber.context.r12;
    //regs->r13 = to_fiber_data->fiber.context.r13;
    //regs->r14 = to_fiber_data->fiber.context.r14;
    //regs->r15 = to_fiber_data->fiber.context.r15;
    regs->flags = to_fiber_data->fiber.context.flags;
    regs->ip = to_fiber_data->fiber.context.rip;
    //asm volatile("fxrstor %0": "+m"(to_fiber_data->fiber.context.others));
    fpu__restore(&to_fiber_data->fiber.context.fpu_context);

    f->private_data = (void*) &to_fiber_data->fiber;
    //leave previous fiber not running anymore
    atomic_set(&current_fiber->running, 0);

    //pr_info("Thread %d - New stack: 0x%llx - New IP: 0x%llx \n", current->pid, (long long unsigned int)regs->sp, (long long unsigned int)regs->ip);

    return to_fiber_data->fid;
}

// Simplistic allocation for FLS
static long openfibers_ioctl_fls_alloc(struct file *f)
{
    fiber_t *current_fiber = (fiber_t *)f->private_data;
    long ret = ++current_fiber->fls_idx;
    if (ret >= MAX_FLS)
        return -1;
    return ret;
}

// Get a FLS value
static void openfibers_ioctl_fls_get(struct file *f, unsigned long idx, unsigned long *value)
{
    fiber_t *current_fiber;
    if (idx >= MAX_FLS)
        return;
    current_fiber = (fiber_t *)f->private_data;
    *value = current_fiber->fls[idx];
    return;
}

// Dummy: we don't actually free FLS here...
static bool openfibers_ioctl_fls_free(struct file *f, long idx)
{
    (void)idx;
    return true;
}

// Store a value in FLS storage
static bool openfibers_ioctl_fls_set(struct file *f, unsigned long idx, long value)
{
    fiber_t *current_fiber;
    if (idx >= MAX_FLS)
        return false;
    current_fiber = (fiber_t *)f->private_data;
    current_fiber->fls[idx] = value;
    return true;
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
        /*{
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
            pr_info("fid=%d start=0x%lx\n", rb_entry(node, struct fibers_node, node)->fid, (long unsigned int)rb_entry(node, struct fibers_node, node)->fiber.start_address);
        }*/
        break;
        
    case OPENFIBERS_IOCTL_CREATE_FIBER:

        if (!access_ok(VERIFY_WRITE, (void *) arg, sizeof(struct fiber_request_t)))
            return -EINVAL;

        return openfibers_ioctl_create_fiber(((struct fiber_request_t *)arg)->stack_address, ((struct fiber_request_t *)arg)->start_address, ((struct fiber_request_t *)arg)->start_args, 0);
        break;

    case OPENFIBERS_IOCTL_SWITCH_TO_FIBER:
        return openfibers_ioctl_switch_to_fiber(f, (fid_t) arg);
        break;

    case OPENFIBERS_IOCTL_CONVERT_TO_FIBER:
        return openfibers_ioctl_convert_to_fiber(f);
        break;
        
    case OPENFIBERS_IOCTL_FLS_ALLOC:
        return openfibers_ioctl_fls_alloc(f);
        break;
    case OPENFIBERS_IOCTL_FLS_FREE:
        return openfibers_ioctl_fls_free(f, (unsigned long)arg);
        break;
    case OPENFIBERS_IOCTL_FLS_GET:
        if (!access_ok(VERIFY_WRITE, (void*) arg, sizeof(struct fls_request_t)))
            return -EINVAL;
        // write result into value, since ioctl only returns an integer in userspace
        openfibers_ioctl_fls_get(f, ((struct fls_request_t *)arg)->idx, &((struct fls_request_t *)arg)->value);
        return 0;
        break;
    case OPENFIBERS_IOCTL_FLS_SET:
        if (!access_ok(VERIFY_READ, (void *) arg, sizeof(struct fls_request_t)))
            return -EINVAL;

        return openfibers_ioctl_fls_set(f, ((struct fls_request_t *)arg)->idx, ((struct fls_request_t *)arg)->value);
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

    // cleanup all the fibers pending
    tgid_fibers_tree_cleanup(&fibers_by_tgid_tree);

    pr_info("cleanup done\n");
    return;
}

module_init(fibers_init);
module_exit(fibers_cleanup);
