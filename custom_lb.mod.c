#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xbd078ac0, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x90c21000, __VMLINUX_SYMBOL_STR(usb_function_unregister) },
	{ 0x8ad3b580, __VMLINUX_SYMBOL_STR(usb_function_register) },
	{ 0x7ee9b961, __VMLINUX_SYMBOL_STR(usb_ep_alloc_request) },
	{ 0x85021e3e, __VMLINUX_SYMBOL_STR(usb_ep_enable) },
	{ 0x599e0e6f, __VMLINUX_SYMBOL_STR(config_ep_by_speed) },
	{ 0x3276ac86, __VMLINUX_SYMBOL_STR(usb_ep_disable) },
	{ 0x67fe4fe2, __VMLINUX_SYMBOL_STR(usb_put_function_instance) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0xa46f2f1b, __VMLINUX_SYMBOL_STR(kstrtouint) },
	{ 0x5e9ad002, __VMLINUX_SYMBOL_STR(config_group_init_type_name) },
	{ 0x6edb8a9d, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0xf4563ef2, __VMLINUX_SYMBOL_STR(__dynamic_dev_dbg) },
	{ 0x820a217b, __VMLINUX_SYMBOL_STR(usb_assign_descriptors) },
	{ 0x11bc2616, __VMLINUX_SYMBOL_STR(usb_ep_autoconfig) },
	{ 0xfb4db846, __VMLINUX_SYMBOL_STR(usb_string_id) },
	{ 0xdb05fb55, __VMLINUX_SYMBOL_STR(usb_interface_id) },
	{ 0x6d670690, __VMLINUX_SYMBOL_STR(mythic_dev_read) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x439f5c6a, __VMLINUX_SYMBOL_STR(mythic_dev_write) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x9cb086da, __VMLINUX_SYMBOL_STR(usb_ep_queue) },
	{ 0xdc3fe0cd, __VMLINUX_SYMBOL_STR(usb_ep_free_request) },
	{ 0x37a3b8ae, __VMLINUX_SYMBOL_STR(dev_err) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xf4bd0b8f, __VMLINUX_SYMBOL_STR(usb_free_all_descriptors) },
	{ 0xdbee26c0, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xf630ab60, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0xb5b47bc8, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0x347b75e7, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x1fdc7df2, __VMLINUX_SYMBOL_STR(_mcount) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=newpcie";

