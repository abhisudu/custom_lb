/* SPDX-License-Identifier: GPL-2.0 */
/*
 * @file    mythic.h
 * @author  Flemin Jose <flemin.jose@ignitarium.com>
 *
 * Copyright (C) Mythic AI, Inc.
 */

#ifndef __MYTHIC_H__
#define __MYTHIC_H__

#include <linux/cdev.h>
#include <linux/ktime.h>
#include <linux/dma-mapping.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/semaphore.h>
#include <linux/errno.h>
#include <linux/version.h>
#include "mythic_ipu_api.h"

#define MYTHIC_IPU_SEMLOCK_COUNT        1

#define MYTHIC_VENDOR_ID                0x1e53
#define MYTHIC_DEVICE_ID                0x9024

#define MYTHIC_DMA_CHANNELS             1
#define MYTHIC_MAX_NUM_BARS             4

#define DRV_MODULE_NAME                 "mythic_new"

#ifdef __MYTHIC_DEBUG__
#define dbg_dev                         pr_info
#else
#define dbg_dev(...)
#endif

/* Debug level */
#ifndef MYTHIC_DEBUG_LEVEL
#define MYTHIC_DEBUG_LEVEL              3 /* Default log level */
#endif

/* Enables debug prints in sync_for_device, sync_for_cpu,
 * getbuf_pin and getbuf_mmap */
#if MYTHIC_DEBUG_LEVEL >= 5
#define dbg_dev_l5                      dbg_dev
#else
#define dbg_dev_l5(...)
#endif

#if MYTHIC_DEBUG_LEVEL >= 4
#define dbg_dev_l4                      dbg_dev
#else
#define dbg_dev_l4(...)
#endif

/* Enables debug prints in pin_user and unpin_user */
#if MYTHIC_DEBUG_LEVEL >= 3
#define dbg_dev_l3                      dbg_dev
#else
#define dbg_dev_l3(...)
#endif

#if MYTHIC_DEBUG_LEVEL >= 2
#define dbg_dev_l2                      dbg_dev
#else
#define dbg_dev_l2(...)
#endif

#if MYTHIC_DEBUG_LEVEL >= 1
#define dbg_dev_l1                      dbg_dev
#else
#define dbg_dev_l1(...)
#endif

#if MYTHIC_DEBUG_LEVEL >= 0
#define dbg_dev_l0                      dbg_dev
#else
#define dbg_dev_l0(...)
#endif


/* Allocation candidate for contiguous memory allocation
 * 0:dma_alloc_coherent()
 * 1:kmalloc()
 */
#define KERNEL_MEM_ALLOCATION           0

/* Selects mmio write/read mechanism
 * 0: uses writel/readl
 * 1: uses memcpy
 */
#define MMIO_RW_MEMCPY                  1

/* pci_ioremap uses write combined API
 * 0: disables write combined ioremap
 * 1: enables write combined ioremap
 */
#if KERNEL_VERSION(4, 3, 0) <= LINUX_VERSION_CODE
#ifdef __aarch64__
#define WRITE_COMBINED_ENABLED          0
#else
#define WRITE_COMBINED_ENABLED          1
#endif
#else
#define WRITE_COMBINED_ENABLED          0
#endif

#ifdef __aarch64__
#define MDMA_MAX_COHERENT_CHUNK         0x20000000 /* 512 MB */
#define MDMA_MAX_CACHED_CHUNK           (MAX_ORDER_NR_PAGES * PAGE_SIZE)
#endif

#ifdef __x86_64__
#define MDMA_MAX_COHERENT_CHUNK         (MAX_ORDER_NR_PAGES * PAGE_SIZE)
#define MDMA_MAX_CACHED_CHUNK           (MAX_ORDER_NR_PAGES * PAGE_SIZE)
                                                        /* 4 MB on x86 */
#endif

#define PCI_READ_REQ_512K               512     /* 512 kB */
#define MYTHIC_MMAP_BUF_SIZE_4KB        4096    /* 4 kB */

#define WORD_NBYTES                     4       /* Number of bytes
                                                   in word */

#define MMIO_BYTE_MODE                  0
#define MMIO_WORD_MODE                  1

/* spinlock enable/disable
 */
#if KERNEL_VERSION(4, 0, 0) <= LINUX_VERSION_CODE
#define spinlock                spin_lock
#define spinunlock              spin_unlock
#define spinlock_irqsave        spin_lock_irqsave
#define spinunlock_irqrestore   spin_unlock_irqrestore
#else
#define spinlock(...)
#define spinunlock(...)
#define spinlock_irqsave(...)
#define spinunlock_irqrestore(...)
#endif

/* Definitions for per process configurations */
#define CFG_MMAP_MODE_MASK              0x1
#define CFG_MMAP_MODE_CACHED            0x0
#define CFG_MMAP_MODE_COHERENT          0x1

enum pci_bar_no {
        BAR_0,
        BAR_1,
        BAR_2,
        BAR_3,
        BAR_4,
        BAR_5,
};

struct buffer_info_pa {
        uint64_t   paddr;       /* physical start address of frame */
        size_t     bytes;       /* bytes in this frame */
};

struct buffer_info_va {
        uint64_t vaddr;
        uint8_t dir;
};

struct buf_list_info {
        uint64_t id;            /* alloc id */
        uint8_t alloc_type;
        uint32_t bytes;
        uint32_t number;        /* number of elements in array below */
        struct buffer_info_va *va_buffers;
        struct buffer_info_pa *pa_buffers;
                                /* pointer to array of paddr and size */
        int32_t pin_count;
        struct sg_table sgt;
        struct page **pages;
        unsigned int pages_nr;
};

struct mem_book_list {
        struct buf_list_info buf_list;
        struct list_head list;
};

struct proc_book_list {
        uint32_t tgid;
        struct task_struct *process_task_struct;
        struct mem_book_list mem_book;
        struct mutex mem_lock;
        uint32_t cfg;                   /* stores per process configurations */
        struct list_head list;
};

struct mythic_dma {
        int major;
        int minor;
        dev_t devno;
        struct cdev cdev;
        int channels;           /* Total dma channels */
        struct class *device_class;
        void *dma_handle;       /* Points to the PCI device */
        void __iomem *bar;
        void __iomem *dma_bar[MYTHIC_MAX_NUM_BARS];
        struct timer_list cleanup_timer;
        uint32_t process_count;
        struct proc_book_list proc_book;
        spinlock_t mdma_mmio_lock;
        spinlock_t list_slock;
};

struct mythic_proc_lock {
        int32_t sema_count;
        int32_t sema_max_count;
        struct semaphore p_lock;
        struct mutex sema_lock;
};

struct mythic_ipu {
        unsigned int idr;
        struct pci_dev *pdev;
        void __iomem *bar[6];
        struct cdev cdev;
        dev_t devno;
        char devname[15];
        struct mythic_dma dma;
        struct semaphore dev_lock;
        struct mythic_proc_lock proc_lock;
};

#endif /* __MYTHIC_H__ */



