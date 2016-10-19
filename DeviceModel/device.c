#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/device.h>

char *author = "RY";
extern struct bus_type virtual_bus;
extern struct device test_bus;

static ssize_t
show_device_author(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", author);
}

void
virtual_bus_release(struct device *dev)
{
	printk("Virtual_device is released.\n");
}

struct device virtual_device = {
//	.bus_id = "test_dev",
	.init_name = "test_dev",
	.bus = &virtual_bus,
	.parent = &test_bus,
	.release = virtual_bus_release,
};

static DEVICE_ATTR(author, S_IRUGO, show_device_author, NULL);

static int __init
device_init(void)
{
	int ret;

	ret = device_register(&virtual_device);
	if (ret) {
		printk("device_register failed.\n");
		return ret;
	}

	if (device_create_file(&virtual_device, &dev_attr_author)) {
		printk(KERN_NOTICE "Unable to creat author attribute.\n");
	}

	printk("Device register success.\n");
	return ret;
}

static void __exit
device_exit(void)
{
	device_unregister(&virtual_device);
}

module_init(device_init);
module_exit(device_exit);
MODULE_AUTHOR("RY");
MODULE_LICENSE("GPL");
