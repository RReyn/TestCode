#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/kernel.h>

extern struct bus_type virtual_bus;
char *author = "RY";

static ssize_t
show_driver_author(struct device_driver *driver, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", author);
}

int
test_driver_remove(struct device *dev)
{
	printk("dirver is removed.\n");
	return 0;
}

int
test_driver_probe(struct device *dev)
{
	printk("Driver can handler the device.\n");
	return 0;
}

struct device_driver virtual_driver = {
	.name = "test_dev",
	.bus = &virtual_bus,
	.probe = test_driver_probe,
	.remove = test_driver_remove,
};

static DRIVER_ATTR(author, S_IRUGO, show_driver_author, NULL);

static int __init
test_driver_init(void)
{
	int ret;

	ret = driver_register(&virtual_driver);
	if (ret) {
		printk(KERN_ERR "driver_register is error.\n");
		return ret;
	}

	if (driver_create_file(&virtual_driver, &driver_attr_author)) {
		printk(KERN_NOTICE"Unable to create author attribute.\n");
	}

	printk("Driver register success.\n");
	return ret;
}

static void __exit
test_driver_exit(void)
{
	driver_unregister(&virtual_driver);
}

module_init(test_driver_init);
module_exit(test_driver_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("RY");


