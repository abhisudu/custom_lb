// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 - 2021, Mythic Inc. All rights reserved.
 */

#ifndef __DMA_MYTHIC_MDMA__
#define __DMA_MYTHIC_MDMA__

#include <linux/version.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/ioctl.h>
#include <linux/irqreturn.h>

int mdma_init(void *dev);
int mdma_pin_user(struct mythic_dma *dma, struct proc_book_list *process,
		PIN_STRUCT *pin_buf);
int mdma_unpin_user(struct mythic_dma *dma,
		struct proc_book_list *process, UNPIN_STRUCT *unpin_buf);
int mdma_sync_for_device(struct mythic_dma *dma,
		struct proc_book_list *process, SYNC_STRUCT *sync_buf);
int mdma_sync_for_cpu(struct mythic_dma *dma,
		struct proc_book_list *process, SYNC_STRUCT *sync_buf);
int mdma_mmap(struct file *filp, struct vm_area_struct *vma);
int mdma_numbuf(struct mythic_dma *dma,
		struct proc_book_list *process, NUMBUF_STRUCT *num_buf);
int mdma_getbuf(struct mythic_dma *dma,
		struct proc_book_list *process, MBUF_LIST *buf_list);
int mdma_get_getbuf_mode(int *mode);
int mdma_set_getbuf_mode(int mode);
int mdma_get_mmap_mode(struct proc_book_list *proc_book, int *mode);
int mdma_set_mmap_mode(struct proc_book_list *proc_book, int mode);
int mdma_write_mmio(struct mythic_dma *dma, MBAR_BUF *mbar_buf);
int mdma_read_mmio(struct mythic_dma *dma, MBAR_BUF *mbar_buf);
int mdma_clear_process_resources(struct mythic_dma *dma,
		struct proc_book_list *process);
void mdma_get_process_node(struct mythic_dma *dma, struct proc_book_list **proc_book);

#endif /* __DMA_MYTHIC_MDMA__ */
