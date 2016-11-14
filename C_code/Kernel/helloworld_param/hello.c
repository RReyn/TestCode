#include <linux/module.h>
#include <linux/init.h>
#include <asm/unistd.h>
#include <linux/stat.h>

static char *whom = "world";
static int howmany = 1;
module_param(howmany, int, S_IRUGO);
module_param(whom, charp, S_IRUGO);

static __init int
hello_init(void)
{
	int i = 0;

	for (i = 0; i < howmany; i++)
		printk(KERN_WARNING "Hello %s\n", whom);
	return 0;
}

static __exit void
hello_exit(void)
{
	printk(KERN_WARNING"Exit hello module\n");	
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
