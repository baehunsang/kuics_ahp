#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("kaerr57");
MODULE_DESCRIPTION("Hspace kernel");

#define DEVICE_NAME "basic_rop"
#define BUFFER_SIZE 0x400

char *g_buf = NULL;

static int module_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "module_open called\n");
	

    g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!g_buf) {
        printk(KERN_INFO "kmalloc failed");
        return -ENOMEM;
    }

    return 0;
}

static ssize_t module_read(struct file *file, char __user *buf, size_t count,
                           loff_t *f_pos) {
    char kbuf[BUFFER_SIZE] = { 0 };

    printk(KERN_INFO "module_read called\n");

    memcpy(kbuf, g_buf, BUFFER_SIZE);
    if (_copy_to_user(buf, kbuf, count)) {
        printk(KERN_INFO "copy_to_user failed\n");
        return -EINVAL;
    }

    return count;
}

static ssize_t module_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *f_pos) {
    char kbuf[BUFFER_SIZE] = { 0 };
    printk(KERN_INFO "module_write called\n");
	if(count > 0x470){
		printk(KERN_INFO "Too long!\n");
		return -EINVAL;
	}
    if (_copy_from_user(kbuf, buf, count)) {
        printk(KERN_INFO "copy_from_user failed\n");
        return -EINVAL;
    }
    memcpy(g_buf, kbuf, BUFFER_SIZE);
	//check
    if((*(uint64_t*)(kbuf + 0x400 + 0) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 1) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 2) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 3) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 4) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 5) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 6) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 7) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 8) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 9) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 10) >= 0xffffffff81c00df0)||
        (*(uint64_t*)(kbuf + 0x400 + 11) >= 0xffffffff81c00df0)
    ){
			printk(KERN_INFO "No ROP!");
			return -EINVAL;
		}
		
    return count;
}

static int module_close(struct inode *inode, struct file *file) {
    printk(KERN_INFO "module_close called\n");
    kfree(g_buf);
    return 0;
}

static struct file_operations module_fops = {
    .owner = THIS_MODULE,
    .read = module_read,
    .write = module_write,
    .open = module_open,
    .release = module_close,
};

static dev_t dev_id;
static struct cdev c_dev;

static int __init module_initialize(void) {
    if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
        printk(KERN_WARNING "Failed to register device\n");
        return -EBUSY;
    }

    cdev_init(&c_dev, &module_fops);
    c_dev.owner = THIS_MODULE;

    if (cdev_add(&c_dev, dev_id, 1)) {
        printk(KERN_WARNING "Failed to add cdev\n");
        unregister_chrdev_region(dev_id, 1);
        return -EBUSY;
    }

    return 0;
}

static void __exit module_cleanup(void) {
    cdev_del(&c_dev);
    unregister_chrdev_region(dev_id, 1);
}

module_init(module_initialize);
module_exit(module_cleanup);
