/*
 * hello_mod.c
 * Output message when this module is loaded/unloaded.
 * Test Linux kernel version: 4.9.80
 */

#include <linux/module.h>

MODULE_DESCRIPTION("Output message when this module is loaded/unloaded.");
MODULE_AUTHOR("sugimoto");
MODULE_LICENSE("GPL");

/* Initialize routine called when module is loaded. */
static int hellomod_init_module(void)
{
    printk("hellomod is loaded.\n");
    printk("Hello world!\n");
    return 0;
}

/* Cleanup routine called when module is unloaded. */
static void hellomod_cleanup_module(void)
{
    printk("hellomod is unloaded.\n");
}

module_init(hellomod_init_module);
module_exit(hellomod_cleanup_module);

