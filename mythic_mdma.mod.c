#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xbd078ac0, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xdbee26c0, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x1fdc7df2, __VMLINUX_SYMBOL_STR(_mcount) },
	{ 0xec2ac905, __VMLINUX_SYMBOL_STR(__ll_sc_atomic_sub_return) },
	{ 0xf33847d3, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0x785a93b4, __VMLINUX_SYMBOL_STR(si_mem_available) },
	{ 0xfa792725, __VMLINUX_SYMBOL_STR(pcie_set_readrq) },
	{ 0x15f4c992, __VMLINUX_SYMBOL_STR(put_zone_device_page) },
	{ 0x3c42cb97, __VMLINUX_SYMBOL_STR(sg_next) },
	{ 0xe03c395d, __VMLINUX_SYMBOL_STR(pcie_capability_clear_and_set_word) },
	{ 0xf630ab60, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0x40c7247c, __VMLINUX_SYMBOL_STR(si_meminfo) },
	{ 0x97fdbab9, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0x6edb8a9d, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xfadf2436, __VMLINUX_SYMBOL_STR(memstart_addr) },
	{ 0x228f4555, __VMLINUX_SYMBOL_STR(kimage_voffset) },
	{ 0xb5b47bc8, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0x8a7a024f, __VMLINUX_SYMBOL_STR(sg_alloc_table) },
	{ 0xb35dea8f, __VMLINUX_SYMBOL_STR(__arch_copy_to_user) },
	{ 0x347b75e7, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x5cd885d5, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x82abd68a, __VMLINUX_SYMBOL_STR(pci_ioremap_bar) },
	{ 0x96220280, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xbe705f5a, __VMLINUX_SYMBOL_STR(remap_pfn_range) },
	{ 0x4829a47e, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xebea8975, __VMLINUX_SYMBOL_STR(dma_common_mmap) },
	{ 0x62aeffaa, __VMLINUX_SYMBOL_STR(sg_free_table) },
	{ 0x1bd47b4c, __VMLINUX_SYMBOL_STR(dump_page) },
	{ 0xe1b77fe6, __VMLINUX_SYMBOL_STR(dma_release_from_coherent_attr) },
	{ 0x390f82db, __VMLINUX_SYMBOL_STR(dma_alloc_from_coherent_attr) },
	{ 0x434071b8, __VMLINUX_SYMBOL_STR(flush_dcache_page) },
	{ 0xbdecb211, __VMLINUX_SYMBOL_STR(dma_ops) },
	{ 0x88db9f48, __VMLINUX_SYMBOL_STR(__check_object_size) },
	{ 0xf2bb45d, __VMLINUX_SYMBOL_STR(__put_page) },
	{ 0x511d7683, __VMLINUX_SYMBOL_STR(get_user_pages_fast) },
	{ 0xb6940761, __VMLINUX_SYMBOL_STR(pcie_capability_read_word) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

