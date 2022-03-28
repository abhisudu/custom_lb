// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 - 2021, Mythic Inc. All rights reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/sysinfo.h>
#include <asm/cacheflush.h>
#include "mythic.h"
#include "mythic_mdma.h"

#define MEM_TYPE_USR_ALLOC		0
#define MEM_TYPE_MMAP_COHERENT		1
#define MEM_TYPE_MMAP_CACHED		2
MODULE_LICENSE("GPL");

spinlock_t pin_sys_lock;
unsigned int mythic_pin_mem_uplimit = 50;
unsigned int mythic_mem_uplimit = 80;
unsigned long long mythic_total_pinned_mem = 0;

static int getbuf_mode = MYTHIC_IOC_BUF_MODE_MAX;

#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 2
static char *task_status(int64_t status)
{
	switch (status) {
	case	0: return "running";
	case	1: return "idle";
	case	-1: return "unrunnable";
	default: return "dead";
	}
}
#endif

/* get_max_mem_chunk_size
 * @brief: get the maximum size of one single chunk of physical memory
 *         used in dma buffers.
 *         This depends on the architecure and the allocation type.
 *         That is user allocated, cached mmap or coherent mmap.
 * @param alloc_type: memory allocation type.
 */
static int get_max_mem_chunk_size(int alloc_type)
{
	switch (alloc_type) {
	case MEM_TYPE_MMAP_COHERENT:
		return MDMA_MAX_COHERENT_CHUNK;
	case MEM_TYPE_MMAP_CACHED:
		return MDMA_MAX_CACHED_CHUNK;
	default:
		return MYTHIC_MMAP_BUF_SIZE_4KB;
	}
}

/* put_all_pages
 * @brief: unpins the pinned pages
 * @param pages: handle to array of pages
 * @param npages: number of pages to unpin
 */
static void put_all_pages(struct page **pages, int npages)
{
	int i;

	for (i = 0; i < npages; i++)
		if (pages[i])
			put_page(pages[i]);
}

/* mdma_skip_pin_user
 * @brief: skips pinning if driver mmap allocated memory is used
 * or user memory is already pinned
 * @param mythic_dev: handle to mythic_ipu structure
 * @param proc_book: handle to process book-keeping node
 * @param pin_buf: handle to PIN_STRUCT structure. pin_buf should contain
 * userspace virtual address and number of bytes to be pinned
 * @return: return true if user page is already pinned
 */
static bool mdma_skip_pin_user(struct mythic_ipu *mythic_dev,
		struct proc_book_list *proc_book,
		PIN_STRUCT *pin_buf)
{
	struct mem_book_list *mem_tmp = NULL, *tmp = NULL;

	list_for_each_entry_safe(mem_tmp, tmp,
			&proc_book->mem_book.list, list) {
		if (pin_buf->vaddr == mem_tmp->buf_list.id) {
			if (mem_tmp->buf_list.alloc_type ==
					MEM_TYPE_USR_ALLOC) {
				mutex_lock(&proc_book->mem_lock);
				mem_tmp->buf_list.pin_count++;
				dbg_dev_l2("Mythic%d: (%s) Memory (vaddr: "
						"0x%llx) already pinned, "
						"skipping pinning",
						mythic_dev->idr,
						__func__, pin_buf->vaddr);
				dbg_dev_l2("Mythic%d: (%s) Pinned memory "
						"(vaddr: 0x%llx) "
						"reference count: %d ",
						mythic_dev->idr, __func__,
						pin_buf->vaddr,
						mem_tmp->buf_list.pin_count);
				mutex_unlock(&proc_book->mem_lock);
				return true;
			} else {
				dbg_dev_l2("Mythic%d: (%s) Found mmap memory "
						"(vaddr: 0x%llx), "
						"skipping pinning",
						mythic_dev->idr, __func__,
						pin_buf->vaddr);
				return true;
			}
		}
	}
	return false;
}

/* mdma_pin_user
 * @brief: pins the pages of user allocated buffer
 * @param dma: handle to mythic_dma structure
 * @param proc_book: handle to process book-keeping node
 * @param pin_buf: handle to PIN_STRUCT structure. pin_buf should contain
 * userspace virtual address and number of bytes to be pinned
 * @return: error code
 */
int mdma_pin_user(struct mythic_dma *dma, struct proc_book_list *proc_book,
		PIN_STRUCT *pin_buf)
{
	int rv = 0, i;
	int nents;
	struct sg_table *sgt;
	unsigned long len;
	uint64_t buf;
	struct scatterlist *sg;
	struct pci_dev *pdev;
	unsigned int pages_nr;
	struct mythic_ipu *mythic_dev;
	struct mem_book_list *mem_tmp = NULL;
	enum dma_data_direction dir = DMA_BIDIRECTIONAL;

	if (!dma || !proc_book || !pin_buf)
		return -EINVAL;

	mythic_dev = container_of(dma, struct mythic_ipu, dma);
	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p\n",
			mythic_dev->idr, __func__, proc_book);
	len = pin_buf->bytes;
	buf = pin_buf->vaddr;
	pdev = (struct pci_dev *)dma->dma_handle;

	dbg_dev_l1("Mythic%d: (%s) User buffer at 0x%llx:%zu\n", mythic_dev->idr,
			__func__, pin_buf->vaddr, pin_buf->bytes);

	/* checks for any driver mmap allocated memory nodes and already pinned
	 * user memory for skipping the pinning */
	rv = mdma_skip_pin_user(mythic_dev, proc_book, pin_buf);
	if (rv)
		return 0;

	/* finds the number pages occupied by the user buffer */
	pages_nr = (((unsigned long)buf + len + PAGE_SIZE - 1) -
			((unsigned long)buf & PAGE_MASK)) >> PAGE_SHIFT;
	if (pages_nr == 0) {
		pr_err("Mythic%d: No pages occupied by the used buffer",
				mythic_dev->idr);
		return -EINVAL;
	}

	/* allocates a list entry for memory book keeping */
	mem_tmp = kzalloc(sizeof(struct mem_book_list), GFP_KERNEL);
	if (mem_tmp == NULL) {
		pr_err("Mythic%d: Allocation of memory node in book-keep "
				"list failed", mythic_dev->idr);
		rv = -ENOMEM;
		goto err_out;
	}

	mem_tmp->buf_list.alloc_type = MEM_TYPE_USR_ALLOC;
	mem_tmp->buf_list.id = buf;
	mem_tmp->buf_list.bytes = pin_buf->bytes;
	sgt = &mem_tmp->buf_list.sgt;

	/* allocates sg table */
	if (sg_alloc_table(sgt, pages_nr, GFP_KERNEL)) {
		pr_err("Mythic%d: Allocation of sg table failed",
				mythic_dev->idr);
		rv = -ENOMEM;
		goto err_out_sg_alloc;
	}

	mem_tmp->buf_list.pages = kcalloc(pages_nr, sizeof(struct page *),
			GFP_KERNEL);
	if (!mem_tmp->buf_list.pages) {
		pr_err("Mythic%d: Allocation of page array failed",
				mythic_dev->idr);
		rv = -ENOMEM;
		goto err_out_page_alloc;
	}

	/* pins the pages */
	rv = get_user_pages_fast((unsigned long)buf, pages_nr,
			1/* write */, mem_tmp->buf_list.pages);
	mem_tmp->buf_list.pages_nr = rv;

	/* no pages were pinned */
	if (rv < 0) {
		pr_err("Mythic%d: Unable to pin down %u user pages, %d",
				mythic_dev->idr, pages_nr, rv);
		goto err_out_pin;
	}

	/* less pages pinned than wanted */
	if (rv != pages_nr) {
		pr_err("Mythic%d: Unable to pin down %u user pages, %d",
				mythic_dev->idr, pages_nr, rv);
		rv = -EFAULT;
		goto err_out_pin;
	}

	/* checks for duplicate pinned pages */
	for (i = 1; i < pages_nr; i++) {
		if (mem_tmp->buf_list.pages[i - 1] ==
				mem_tmp->buf_list.pages[i]) {
			pr_err("Mythic%d: Duplicate pages %d, %d",
					mythic_dev->idr, i - 1, i);
			rv = -EFAULT;
			goto err_out_pin;
		}
	}

	sg = sgt->sgl;
	for (i = 0; i < pages_nr; i++, sg = sg_next(sg)) {
		unsigned int offset = offset_in_page(buf);
		unsigned int nbytes = min_t(unsigned int, PAGE_SIZE -
				offset, len);

		flush_dcache_page(mem_tmp->buf_list.pages[i]);
		sg_set_page(sg, mem_tmp->buf_list.pages[i],
				nbytes, offset);
		buf += nbytes;
		len -= nbytes;
	}

	if (len) {
		pr_err("Mythic%d: Invalid length in sg list pages",
				mythic_dev->idr);
		rv = -EINVAL;
		goto err_out_pin;
	}

	sg = sgt->sgl;
	nents = pci_map_sg(pdev, sg, sgt->orig_nents, dir);
	if (!nents) {
		pr_err("Mythic%d: pci map sg failed, sgt 0x%p",
				mythic_dev->idr, sgt);
		pr_err("Mythic%d: orig_nents : %d, nents : %d\n",
				mythic_dev->idr, sgt->orig_nents, nents);
		goto err_out_sg_map;
	}
	sgt->nents = nents;
	mem_tmp->buf_list.number = nents;

	/* allocates memory for book-keeping dma descriptor */
	mem_tmp->buf_list.pa_buffers = kmalloc_array(sgt->nents,
			sizeof(struct buffer_info_pa), GFP_KERNEL);
	if (mem_tmp->buf_list.pa_buffers == NULL) {
		pr_err("Mythic%d: Buffer allocation for dma descriptors "
				"failed", mythic_dev->idr);
		rv = -ENOMEM;
		goto err_out_pa_buf_alloc;
	}

	/* book-keeps dma address and length */
	for (i = 0, sg = sgt->sgl; i < sgt->nents; i++,
			sg = sg_next(sg)) {
		mem_tmp->buf_list.pa_buffers[i].paddr = sg_dma_address(sg);
		mem_tmp->buf_list.pa_buffers[i].bytes = sg_dma_len(sg);
		dbg_dev_l4("Mythic%d: (%s) page:%d "
				"dma_addr :0x%llx, bytes:%zu",
				mythic_dev->idr, __func__, i,
				mem_tmp->buf_list.pa_buffers[i].paddr,
				mem_tmp->buf_list.pa_buffers[i].bytes);
	}
	mutex_init(&proc_book->mem_lock);
	mutex_lock(&proc_book->mem_lock);
	mem_tmp->buf_list.pin_count++;
	dbg_dev_l2("Mythic%d: (%s) Pinned memory (vaddr: 0x%llx) "
			"reference count: %d", mythic_dev->idr, __func__,
			pin_buf->vaddr, mem_tmp->buf_list.pin_count);
	mutex_unlock(&proc_book->mem_lock);

	spinlock(&dma->list_slock);
	/* Adding memory node to the memory book-keeping list */
	list_add(&mem_tmp->list, &proc_book->mem_book.list);
	spinunlock(&dma->list_slock);
	spinlock(&pin_sys_lock);
	mythic_total_pinned_mem += mem_tmp->buf_list.bytes;
	spinunlock(&pin_sys_lock);
	dbg_dev_l0("Mythic%d: (%s) Pinned user buffer at 0x%llx:%zu\n",
			mythic_dev->idr, __func__,
			pin_buf->vaddr, pin_buf->bytes);
	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p, &proc_book->mem_book.list = "
			"0x%p\n", mythic_dev->idr, __func__, proc_book,
			&proc_book->mem_book.list);
	return 0;

err_out_pa_buf_alloc:
err_out_sg_map:
	pci_unmap_sg(pdev, sg, nents, dir);
err_out_pin:
	put_all_pages(mem_tmp->buf_list.pages, mem_tmp->buf_list.pages_nr);
	kfree(mem_tmp->buf_list.pages);
	mem_tmp->buf_list.pages = NULL;
err_out_page_alloc:
	sg_free_table(sgt);
err_out_sg_alloc:
	kfree(mem_tmp);
err_out:
	return rv;
}

/* free_mem_node_resources
 * @brief: cleanup book-keeping of pages pinned
 * @param dma: handle to mythic_dma structure
 * @param mem_tmp: handle to memory book-keeping node
 * @return: error code
 */
static int free_mem_node_resources(struct mythic_dma *dma,
		struct mem_book_list *mem_tmp)
{
	struct sg_table *sgt;
	struct pci_dev *pdev;
	enum dma_data_direction dir = DMA_BIDIRECTIONAL;

	pdev = (struct pci_dev *)dma->dma_handle;
	if (mem_tmp == NULL)
		return -EFAULT;
	kfree(mem_tmp->buf_list.pa_buffers);
	mem_tmp->buf_list.pa_buffers = NULL;
	sgt = &mem_tmp->buf_list.sgt;
	pci_unmap_sg(pdev, sgt->sgl, sgt->orig_nents,
			dir);
	put_all_pages(mem_tmp->buf_list.pages,
			mem_tmp->buf_list.pages_nr);
	kfree(mem_tmp->buf_list.pages);
	mem_tmp->buf_list.pages = NULL;
	sg_free_table(sgt);
	spinlock(&pin_sys_lock);
	mythic_total_pinned_mem -= mem_tmp->buf_list.bytes;
	spinunlock(&pin_sys_lock);
	kfree(mem_tmp);
	return 0;
}

/* mdma_skip_unpin_user
 * @brief: skips unpinning if driver mmap allocated memory is used
 * or user memory is already pinned
 * @param dma: handle to mythic_dma structure
 * @param proc_book: handle to process book-keeping node
 * @param unpin_buf: handle to UNPIN_STRUCT structure. unpin_buf
 * should contain userspace virtual address and forced flag
 * @return: retrun true if pinned memory is referenced
 */
static bool mdma_skip_unpin_user(struct mythic_dma *dma,
		struct proc_book_list *proc_book,
		UNPIN_STRUCT *unpin_buf)
{
	struct mem_book_list *mem_tmp = NULL, *tmp = NULL;
#if defined(__MYTHIC_DEBUG__)
	struct mythic_ipu *mythic_dev;

	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p\n",
			mythic_dev->idr, __func__, proc_book);
	list_for_each_entry_safe(mem_tmp, tmp,
			&proc_book->mem_book.list, list) {
		if (unpin_buf->buf.vaddr == mem_tmp->buf_list.id) {
			if ((mem_tmp->buf_list.alloc_type ==
					MEM_TYPE_USR_ALLOC) &&
					(unpin_buf->forced == 0)) {
				mutex_lock(&proc_book->mem_lock);
				if (mem_tmp->buf_list.pin_count > 1) {
					mem_tmp->buf_list.pin_count--;
					dbg_dev_l3("Mythic%d: (%s) Pinned memory "
						"(vaddr: 0x%llx_"
						"reference count: %d ",
						mythic_dev->idr, __func__,
						unpin_buf->buf.vaddr,
						mem_tmp->buf_list.pin_count);
					dbg_dev_l3("Mythic%d: (%s) Pinned memory"
						" (vaddr: 0x%llx)"
						" in use, skipping unpinning",
						mythic_dev->idr, __func__,
						unpin_buf->buf.vaddr);
					mutex_unlock(&proc_book->mem_lock);
					return true;
				}
				mutex_unlock(&proc_book->mem_lock);
			} else {
				dbg_dev_l3("Mythic%d: (%s) Found mmap memory"
						" (vaddr: 0x%llx),"
						" skipping unpinning",
						mythic_dev->idr, __func__,
						unpin_buf->buf.vaddr);
				return true;
			}
		}
	}
	return false;
}

/* mdma_unpin_mem_node_buffer
 * @brief: skips unpinning if driver mmap allocated memory is used
 * or user memory is already pinned
 * @param dma: handle to mythic_dma structure
 * @param proc_book: handle to process book-keeping node
 * @param unpin_buf: handle to UNPIN_STRUCT structure. unpin_buf
 * should contain userspace virtual address and forced flag
 * @return: retrun error
 */
static int mdma_unpin_mem_node_buffer(struct mythic_dma *dma,
		struct proc_book_list *proc_book,
		UNPIN_STRUCT *unpin_buf)
{
	int rv = -EFAULT;
	struct list_head *pos, *q;
	struct mem_book_list *mem_tmp = NULL;
#if defined(__MYTHIC_DEBUG__)
	struct mythic_ipu *mythic_dev;

	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p\n",
			mythic_dev->idr, __func__, proc_book);
	list_for_each_safe(pos, q, &proc_book->mem_book.list) {
		rv = -EIO;
		mem_tmp = list_entry(pos, struct mem_book_list, list);
		if (mem_tmp == NULL)
			continue;
		if (unpin_buf->forced == 0) {
			if (unpin_buf->buf.vaddr == mem_tmp->buf_list.id) {
				mutex_lock(&proc_book->mem_lock);
				mem_tmp->buf_list.pin_count = 0;
				mutex_unlock(&proc_book->mem_lock);
				spinlock(&dma->list_slock);
				list_del(pos);
				spinunlock(&dma->list_slock);
				rv = free_mem_node_resources(dma, mem_tmp);
				dbg_dev_l1("Mythic%d: (%s) Unpinned user"
						" buffer at 0x%llx:%zu\n",
						mythic_dev->idr, __func__,
						unpin_buf->buf.vaddr,
						unpin_buf->buf.bytes);
				break;
			}
		} else if (unpin_buf->forced == 1) {
			mutex_lock(&proc_book->mem_lock);
			mem_tmp->buf_list.pin_count = 0;
			mutex_unlock(&proc_book->mem_lock);
			spinlock(&dma->list_slock);
			list_del(pos);
			spinunlock(&dma->list_slock);
			rv = free_mem_node_resources(dma, mem_tmp);
			dbg_dev_l1("Mythic%d: (%s) Forced unpin of user"
					" buffer at 0x%llx:%zu\n",
					mythic_dev->idr, __func__,
					unpin_buf->buf.vaddr,
					unpin_buf->buf.bytes);
		}
	}
	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p, &proc_book->mem_book.list"
			" = 0x%p\n", mythic_dev->idr, __func__, proc_book,
			&proc_book->mem_book.list);
	return rv;
}

/* mdma_unpin_user
 * @brief: unpinning user pages
 * @param dma: handle to mythic_dma structure
 * @param proc_book: handle to process book-keeping node
 * @param unpin_buf: handle to UNPIN_STRUCT structure. unpin_buf
 * should contain userspace virtual address and forced flag
 * @return: error code
 */
int mdma_unpin_user(struct mythic_dma *dma,
		struct proc_book_list *proc_book,
		UNPIN_STRUCT *unpin_buf)
{
	int rv = -EIO;
#if defined(__MYTHIC_DEBUG__)
	struct mythic_ipu *mythic_dev;
#endif

	if (!dma || !proc_book || !unpin_buf || (unpin_buf->forced > 1))
		return -EINVAL;

#if defined(__MYTHIC_DEBUG__)
	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	dbg_dev_l1("Mythic%d: (%s) User buffer at 0x%llx:%zu\n", mythic_dev->idr,
			__func__, unpin_buf->buf.vaddr,
			unpin_buf->buf.bytes);
	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p, &proc_book->"
			"mem_book.list = 0x%p\n", mythic_dev->idr,
			__func__, proc_book, &proc_book->mem_book.list);

	/* checks for any driver mmap allocated memory nodes and already pinned
	 * user memory for skipping the unpinning */
	rv = mdma_skip_unpin_user(dma, proc_book, unpin_buf);
	if (rv)
		return 0;

	rv = mdma_unpin_mem_node_buffer(dma, proc_book, unpin_buf);
	dbg_dev_l0("Mythic%d: (%s) Unpinned user buffer at 0x%llx:%zu\n",
			mythic_dev->idr, __func__, unpin_buf->buf.vaddr,
			unpin_buf->buf.bytes);
	return rv;
}

/* mdma_sync_for_device
 * @brief: syncs the user allocated buffer for dma
 * @param dma: handle to mythic_dma structure
 * @param proc_book: handle to process book-keeping node
 * @param sync_buf: handle to SYNC_STRUCT structure. sync_buf should
 * contain userspace virtual address
 * @return: error code
 */
int mdma_sync_for_device(struct mythic_dma *dma,
		struct proc_book_list *proc_book,
		SYNC_STRUCT *sync_buf)
{
	int rv = -EIO;
	int i;
	dma_addr_t paddr;
	int bytes;
	struct list_head *pos, *q;
	struct pci_dev *pdev;
	struct sg_table *sgt;
	struct mem_book_list *mem_tmp = NULL;
	enum dma_data_direction dir = DMA_BIDIRECTIONAL;
#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 0
	struct mythic_ipu *mythic_dev;
#endif

	if (!dma || !proc_book || !sync_buf)
		return -EINVAL;

#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 0
	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	pdev = (struct pci_dev *)dma->dma_handle;

	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p\n",
			mythic_dev->idr, __func__, proc_book);

	list_for_each_safe(pos, q, &proc_book->mem_book.list) {
		rv = -EIO;
		mem_tmp = list_entry(pos, struct mem_book_list, list);
		if (mem_tmp == NULL)
			continue;
		if (sync_buf->vaddr != mem_tmp->buf_list.id)
			continue;
		dbg_dev_l0("Mythic%d: (%s) vaddr:0x%llx", mythic_dev->idr,
				__func__, sync_buf->vaddr);
		if (mem_tmp->buf_list.alloc_type == MEM_TYPE_USR_ALLOC) {
			sgt = &mem_tmp->buf_list.sgt;
			pci_dma_sync_sg_for_device(pdev, sgt->sgl,
					sgt->orig_nents, dir);
		} else {
			for (i = 0; i < mem_tmp->buf_list.number; i++) {
				paddr = mem_tmp->buf_list.pa_buffers[i].paddr;
				bytes = mem_tmp->buf_list.pa_buffers[i].bytes;
				dma_sync_single_for_device(&pdev->dev, paddr,
						bytes, dir);
			}
		}
		rv = 0;
		break;
	}
	return rv;
}

/* mdma_sync_for_cpu
 * @brief: syncs the user allocated buffer for cpu
 * @param dma: handle to mythic_dma structure
 * @param proc_book: handle to process book-keeping node
 * @param sync_buf: handle to SYNC_STRUCT structure. sync_buf should
 * contain userspace virtual address
 * @return: error code
 */
int mdma_sync_for_cpu(struct mythic_dma *dma,
		struct proc_book_list *proc_book,
		SYNC_STRUCT *sync_buf)
{

	int rv = -EIO;
	int i;
	dma_addr_t paddr;
	int bytes;
	struct list_head *pos, *q;
	struct pci_dev *pdev;
	struct sg_table *sgt;
	struct mem_book_list *mem_tmp = NULL;
	enum dma_data_direction dir = DMA_BIDIRECTIONAL;
#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 0
	struct mythic_ipu *mythic_dev;
#endif
	if (!dma || !proc_book || !sync_buf)
		return -EINVAL;

#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 0
	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	pdev = (struct pci_dev *)dma->dma_handle;

	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p\n",
			mythic_dev->idr, __func__, proc_book);

	list_for_each_safe(pos, q, &proc_book->mem_book.list) {
		rv = -EIO;
		mem_tmp = list_entry(pos, struct mem_book_list, list);
		if (mem_tmp == NULL)
			continue;
		if (sync_buf->vaddr != mem_tmp->buf_list.id)
			continue;
		dbg_dev_l0("Mythic%d: (%s) vaddr:0x%llx", mythic_dev->idr,
				__func__, sync_buf->vaddr);
		if (mem_tmp->buf_list.alloc_type == MEM_TYPE_USR_ALLOC) {
			sgt = &mem_tmp->buf_list.sgt;
			pci_dma_sync_sg_for_cpu(pdev, sgt->sgl,
					sgt->orig_nents, dir);
		} else {
			for (i = 0; i < mem_tmp->buf_list.number; i++) {
				paddr = mem_tmp->buf_list.pa_buffers[i].paddr;
				bytes = mem_tmp->buf_list.pa_buffers[i].bytes;
				dma_sync_single_for_cpu(&pdev->dev, paddr,
						bytes, dir);
			}
		}
		rv = 0;
		break;
	}
	return rv;
}

/* mdma_clear_process_resources
 * @param dma: handle to mythic_dma structure
 * @param proc_book: handle to process book-keeping node
 * @return: error code
 */
int mdma_clear_process_resources(struct mythic_dma *dma,
		struct proc_book_list *proc_book)
{
	int rv = -EFAULT;
	struct list_head *pos, *q;
	struct mem_book_list *mem_tmp = NULL;
#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 2
	struct mythic_ipu *mythic_dev;
#endif

	if (!dma || !proc_book)
		return -EINVAL;

#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 2
	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif

	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p\n",
			mythic_dev->idr, __func__, proc_book);

	/* Unpins and de-allocates all memory resources */
	list_for_each_safe(pos, q, &proc_book->mem_book.list) {
		mem_tmp = list_entry(pos, struct mem_book_list, list);
		if (mem_tmp == NULL)
			continue;
		/* Delete memory nodes of both driver mmap and user
		 * allocated buffers */
		spinlock(&dma->list_slock);
		list_del(pos);
		spinunlock(&dma->list_slock);
		/* Clears resources allocated for user allocated buffers.
		 * Driver mmap resource allocation is skipped since they
		 * are cleaned automatically from vm_close() function */
		if (mem_tmp->buf_list.alloc_type == MEM_TYPE_USR_ALLOC) {
			dbg_dev_l2("Mythic%d: (%s) Clearing user memory"
					" resources at vaddr:0x%llx",
					mythic_dev->idr, __func__,
					mem_tmp->buf_list.id);
			rv = free_mem_node_resources(dma, mem_tmp);
		}
	}
	return rv;
}

/* mdma_set_mmap_mode
 * @param proc_book: pointer to the process book keeping structure
 *                   for the current process
 * @param mode: mmap mode
 * @return: error code
 */
int mdma_set_mmap_mode(struct proc_book_list *proc_book, int mode)
{
	if (mode == MYTHIC_MMAP_MODE_CACHED)
		mode = CFG_MMAP_MODE_CACHED;
	else if (mode == MYTHIC_MMAP_MODE_COHERENT)
		mode = CFG_MMAP_MODE_COHERENT;
	else
		return -EINVAL;

	proc_book->cfg &= ~(CFG_MMAP_MODE_MASK);
	proc_book->cfg |= mode;

	return 0;
}

/* mdma_get_mmap_mode
 * @param proc_book: pointer to the process book keeping structure
 *                   for the current process
 * @param *mode: mmap mode output argument
 * @return: error code
 */
int mdma_get_mmap_mode(struct proc_book_list *proc_book, int *mode)
{
	if (mode == NULL)
		return -EINVAL;

	if ((proc_book->cfg & CFG_MMAP_MODE_MASK) == CFG_MMAP_MODE_CACHED)
		*mode = MYTHIC_MMAP_MODE_CACHED;
	else
		*mode = MYTHIC_MMAP_MODE_COHERENT;

	return 0;
}

/* mdma_get_getbuf_mode
 * @param mode: pointer to variable to get mode of getbuf ioctl.
 * @return: error code
 */
int mdma_get_getbuf_mode(int *mode)
{
	if (mode == NULL)
		return -EINVAL;

	*mode = getbuf_mode;
	return 0;
}


/* mdma_set_getbuf_mode
 * @param mode: variable to mode of getbuf ioctl.
 * @return: error code
 */
int mdma_set_getbuf_mode(int mode)
{
	if (getbuf_mode == MYTHIC_IOC_BUF_MODE_MAX ||
			getbuf_mode == MYTHIC_IOC_BUF_MODE_4KB) {
		getbuf_mode = mode;
		return 0;
	} else {
		return -EINVAL;
	}
}


/* get_pinned_pa_buffers
 * brief: Fetches the buffer storing physical addresses
 * of user pinned memory.
 * @param dma: handle to mythic_dma structure
 * @param mem_tmp: handle to memory book-keeping node
 * @param pa_buffers: buffer handle to return the physical
 * addresses
 */
static void get_pinned_pa_buffers(struct mythic_dma *dma,
		struct mem_book_list *mem_tmp,
		struct buffer_info_pa *pa_buffers)
{
	int i, j;
	int64_t rem_bytes;
	uint64_t pg_addr, pg_bytes;
	uint64_t idx = 0, pg_offset = 0;
#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 4
	struct mythic_ipu *mythic_dev;
#endif
	struct buffer_info_pa *pa_buffers_ptr;

#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 4
	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	for (i = 0; i < mem_tmp->buf_list.number; i++) {
		pg_bytes = PAGE_SIZE;
		pa_buffers_ptr = mem_tmp->buf_list.pa_buffers;
		rem_bytes = pa_buffers_ptr[i].bytes;
		pg_addr = pa_buffers_ptr[i].paddr;
		if ((pa_buffers_ptr[i].paddr & 0xFFF) != 0) {
			pg_offset = pa_buffers_ptr[i].paddr & 0xFFF;
			pg_bytes = (PAGE_SIZE - pg_offset);
		}
		if (rem_bytes < pg_bytes)
			pg_bytes = rem_bytes;
		dbg_dev_l4("Mythic%d: (%s) pg_offset = %llx\n",
				mythic_dev->idr, __func__, pg_offset);
		for(j = 0; rem_bytes > 0; j++) {
			pa_buffers[idx].paddr = pg_addr;
			pa_buffers[idx].bytes = pg_bytes;
			dbg_dev_l4("Mythic%d: (%s) pa_buffers[%lld].paddr"
					" = %llx\n", mythic_dev->idr,
					__func__, idx,
					pa_buffers[idx].paddr);
			dbg_dev_l4("Mythic%d: (%s) pa_buffers[%lld].bytes"
					" = %lx\n", mythic_dev->idr,
					__func__, idx,
					pa_buffers[idx].bytes);
			rem_bytes -= pg_bytes;
			pg_addr += pg_bytes;

			if (rem_bytes >= PAGE_SIZE)
				pg_bytes = PAGE_SIZE;
			else
				pg_bytes = rem_bytes;
			idx++;
		}
	}
}

/* get_mmap_pa_buffers
 * brief: Fetches the buffer storing physical addresses
 * of mmaped memory.
 * @param dma: handle to mythic_dma structure
 * @param mem_tmp: handle to memory book-keeping node
 * @param pa_buffers: buffer handle to return the physical
 * addresses
 */
static void get_mmap_pa_buffers(struct mythic_dma *dma,
		struct mem_book_list *mem_tmp,
		struct buffer_info_pa *pa_buffers)
{
	int i, j;
	int64_t rem_bytes, chunk_size;
	uint64_t idx = 0;
#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 4
	struct mythic_ipu *mythic_dev;
#endif
	struct buffer_info_pa *pa_buffers_ptr;
	uint64_t mythic_mmap_buf_size;
	int64_t max_chunk_size;

	max_chunk_size = get_max_mem_chunk_size(mem_tmp->buf_list.alloc_type);

#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 4
	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	if (getbuf_mode == MYTHIC_IOC_BUF_MODE_MAX)
		mythic_mmap_buf_size = max_chunk_size;
	else
		mythic_mmap_buf_size = MYTHIC_MMAP_BUF_SIZE_4KB;

	for (i = 0; i < mem_tmp->buf_list.number; i++) {
		pa_buffers_ptr = mem_tmp->buf_list.pa_buffers;
		rem_bytes = pa_buffers_ptr[i].bytes;
		chunk_size = 0;
		j = 0;
		while ((chunk_size < max_chunk_size) && (rem_bytes > 0)) {
			pa_buffers[idx].paddr = pa_buffers_ptr[i].paddr +
				j*mythic_mmap_buf_size;
			if (rem_bytes >= mythic_mmap_buf_size)
				pa_buffers[idx].bytes = mythic_mmap_buf_size;
			else
				pa_buffers[idx].bytes = rem_bytes;
			rem_bytes -= mythic_mmap_buf_size;
			chunk_size += mythic_mmap_buf_size;
			dbg_dev_l4("Mythic%d: (%s) pa_buffers[%lld].paddr"
					" = %llx\n",
					mythic_dev->idr, __func__, idx,
					pa_buffers[idx].paddr);
			dbg_dev_l4("Mythic%d: (%s) pa_buffers[%lld].bytes"
					" = %lx\n",
					mythic_dev->idr, __func__, idx,
					pa_buffers[idx].bytes);
			idx++;
			j++;
		}
	}
}

/* mdma_getbuf
 * @param dma: handle to mythic_dma structure
 * @param proc_book: handle to process book-keeping node
 * @param buf_list: handle to MBUF_LIST structure.
 * buf_list should contain valid buffer id, number of pages,
 * handle to memory that stores physical address and size of each page
 * or buffer
 * @return: error code
 */
int mdma_getbuf(struct mythic_dma *dma,
		struct proc_book_list *proc_book,
		MBUF_LIST *buf_list)
{
	int rv = -EFAULT;
	struct buffer_info_pa *pa_buffers;
	struct mem_book_list *mem_tmp = NULL, *tmp = NULL;
	struct mythic_ipu *mythic_dev;

	if (!dma || !proc_book || !buf_list)
		return -EINVAL;

	mythic_dev = container_of(dma, struct mythic_ipu, dma);

	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p\n",
			mythic_dev->idr, __func__, proc_book);

	list_for_each_entry_safe(mem_tmp, tmp,
			&proc_book->mem_book.list, list) {
		if (buf_list->buf.vaddr == mem_tmp->buf_list.id) {
			dbg_dev_l0("Mythic%d: (%s) vaddr: 0x%llx",
					mythic_dev->idr,
					__func__, buf_list->buf.vaddr);
			/* allocates memory for storing dma
			 * descriptor */
			pa_buffers = kmalloc_array(buf_list->number,
					sizeof(struct buffer_info_pa),
					GFP_KERNEL);
			if (pa_buffers == NULL) {
				pr_err("Mythic%d: Buffer allocation for "
						"storing dma descriptors "
						"failed", mythic_dev->idr);
				return -ENOMEM;
			}

			if (mem_tmp->buf_list.alloc_type == MEM_TYPE_USR_ALLOC)
				get_pinned_pa_buffers(dma, mem_tmp, pa_buffers);
			else
				get_mmap_pa_buffers(dma, mem_tmp, pa_buffers);

			rv = copy_to_user((buffer *)buf_list->buffers,
					pa_buffers,
					sizeof(struct buffer_info_pa)*
					buf_list->number);
			kfree(pa_buffers);
			pa_buffers = NULL;
			if (rv)
				pr_err("Mythic%d: Could not copy %d "
						"bytes to userspace",
						mythic_dev->idr, rv);
			return rv;
		}
	}
	return rv;
}

/* get_pinned_num_buffers
 * brief: Returns of number of buffers taken by the pinned memory
 * @param buf_list: handle to buf_list_info structure
 * @param pa_buffers: handle to buffer storing physical
 * addresses
 * return: number of buffers
 */
static int64_t get_pinned_num_buffers(struct buf_list_info *buf_list,
		struct buffer_info_pa *pa_buffers)
{
	int i, j;
	int64_t rem_bytes, numbuf = 0;
	uint64_t pg_offset, pg_bytes;

	for (i = 0; i < buf_list->number; i++) {
		pg_bytes = PAGE_SIZE;
		rem_bytes = pa_buffers[i].bytes;
		if ((pa_buffers[i].paddr & 0xFFF) != 0) {
			pg_offset = pa_buffers[i].paddr & 0xFFF;
			pg_bytes = (PAGE_SIZE - pg_offset);
		}
		if (rem_bytes < pg_bytes)
			pg_bytes = rem_bytes;
		for(j = 0; rem_bytes > 0; j++) {
			numbuf++;
			rem_bytes -= pg_bytes;
			if (rem_bytes >= PAGE_SIZE)
				pg_bytes = PAGE_SIZE;
			else
				pg_bytes = rem_bytes;
		}
	}
	return numbuf;
}

/* get_mmap_num_buffers
 * brief: Returns of number of buffers taken by the pinned memory
 * @param buf_list: handle to buf_list_info structure
 * @param pa_buffers: handle to buffer storing physical
 * addresses
 * return: number of buffers
 */
static int64_t get_mmap_num_buffers(struct buf_list_info *buf_list,
		struct buffer_info_pa *pa_buffers)
{
	int i;
	int64_t rem_bytes, numbuf = 0, chunk_size;
	int64_t max_chunk_size;

	max_chunk_size = get_max_mem_chunk_size(buf_list->alloc_type);

	if (getbuf_mode == MYTHIC_IOC_BUF_MODE_MAX)
		return buf_list->number;

	for (i = 0; i < buf_list->number; i++) {
		rem_bytes = pa_buffers[i].bytes;
		chunk_size = 0;
		while ((chunk_size < max_chunk_size) && (rem_bytes > 0)) {
			rem_bytes -= MYTHIC_MMAP_BUF_SIZE_4KB;
			chunk_size += MYTHIC_MMAP_BUF_SIZE_4KB;

			numbuf++;
		}
	}
	return numbuf;
}

/* mdma_numbuf
 * @param dma: handle to mythic_dma structure
 * @param proc_book: handle to process book-keeping node
 * @param num_buf: handle to NUMBUF_STRUCT structure.
 * @return: error code
 */
int mdma_numbuf(struct mythic_dma *dma,
		struct proc_book_list *proc_book,
		NUMBUF_STRUCT *num_buf)
{
	int64_t numbuf = 0;
	struct mem_book_list *mem_tmp = NULL;
	struct buf_list_info *buf_list;
	struct buffer_info_pa *pa_buffers;
	struct mythic_ipu *mythic_dev;

	if (!dma || !proc_book || !num_buf)
		return -EINVAL;

	mythic_dev = container_of(dma, struct mythic_ipu, dma);

	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p\n",
			mythic_dev->idr, __func__, proc_book);

	spinlock(&dma->list_slock);
	list_for_each_entry(mem_tmp,
			&proc_book->mem_book.list, list) {
		pa_buffers = mem_tmp->buf_list.pa_buffers;
		buf_list = &mem_tmp->buf_list;
		if (num_buf->buf.vaddr == buf_list->id) {
			dbg_dev_l0("Mythic%d: (%s) vaddr: 0x%llx",
					mythic_dev->idr, __func__,
					num_buf->buf.vaddr);
			if (buf_list->alloc_type == MEM_TYPE_USR_ALLOC) {
				numbuf = get_pinned_num_buffers(buf_list,
						pa_buffers);
			} else {
				numbuf = get_mmap_num_buffers(buf_list,
						pa_buffers);
			}
			dbg_dev_l0("Mythic%d: (%s) numbuf :%lld\n",
					mythic_dev->idr, __func__, numbuf);
			goto unlock;
		}
	}
	pr_err("Mythic%d: Unable find the memory node of requested "
			"vaddr: 0x%llx", mythic_dev->idr, num_buf->buf.vaddr);
	numbuf = -EFAULT;
unlock:
	spinunlock(&dma->list_slock);
	return numbuf;
}

static void add_new_process_node(struct mythic_dma *dma,
		struct proc_book_list **proc_book)
{
	struct proc_book_list *proc_tmp = NULL;
#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 1
	struct mythic_ipu *mythic_dev;

	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	proc_tmp = kmalloc(sizeof(*proc_tmp), GFP_KERNEL);
	proc_tmp->tgid = current->tgid;
	proc_tmp->process_task_struct = current;
	proc_tmp->cfg = CFG_MMAP_MODE_CACHED;

	INIT_LIST_HEAD(&(proc_tmp->mem_book.list));
	spinlock(&dma->list_slock);
	/* Adding process node to the process book-keeping list */
	list_add(&(proc_tmp->list), &dma->proc_book.list);
	*proc_book = proc_tmp;
	dma->process_count++;
	spinunlock(&dma->list_slock);
	dbg_dev_l1("Mythic%d: (%s) New process node added (TGID:%d)",
			mythic_dev->idr, __func__, proc_tmp->tgid);
	dbg_dev_l2("Mythic%d: (%s) proc_book = 0x%p, "
			"&proc_book->mem_book.list = 0x%p "
			"proc_tmp->process_task_struct = 0x%p, "
			"current = 0x%p", mythic_dev->idr, __func__,
			*proc_book, &(*proc_book)->mem_book.list,
			proc_tmp->process_task_struct, current);
}

void mdma_get_process_node(struct mythic_dma *dma,
		struct proc_book_list **process_book)
{
	struct proc_book_list *tmp = NULL;
	struct proc_book_list *proc_book;
	int new_process_flag = 1;
	struct mythic_ipu *mythic_dev;

	mythic_dev = container_of(dma, struct mythic_ipu, dma);
	list_for_each_entry_safe(proc_book, tmp,
			&dma->proc_book.list, list) {
		dbg_dev_l3("Mythic%d: (%s) proc_book->tgid = %d,"
				"current->tgid = %d, current->state = %ld,"
				"current = 0x%p",
				mythic_dev->idr, __func__,
				proc_book->tgid, current->tgid,
				current->state, current );
		if (!proc_book) {
			pr_err("Mythic%d: %s: Invalid process book-keep node",
					mythic_dev->idr, __func__);
			*process_book = NULL;
			return;
		}

		if (proc_book->tgid ==  current->tgid) {
			dbg_dev_l1("Mythic%d: (%s) Process (PID: %d, TGID: %d)"
					" already registered\n",
					mythic_dev->idr, __func__,
					current->pid, current->tgid);
			new_process_flag = 0;
			break;
		}
		dbg_dev_l2("Mythic%d: (%s) TGID: %d, Process status: %s\n",
			mythic_dev->idr, __func__, proc_book->tgid,
			task_status(proc_book->process_task_struct->state));
	}
	if (new_process_flag) {
		add_new_process_node(dma, &proc_book);
		dbg_dev_l1("Mythic%d: (%s) New process "
				"(PID: %d, TGID: %d) registered\n",
				mythic_dev->idr, __func__,
				current->pid, current->tgid);
	}
	*process_book = proc_book;
}

/* vm_close
 * @brief: Handles the deallocation of contiguous memory on munmap call
 * @param vma: handle to vm_area_struct
 */
static void vm_close(struct vm_area_struct *vma)
{
	uint64_t id;
	int buf_count, i;
	struct list_head *pos, *q;
	struct mythic_dma *dma;
#if defined(__aarch64__) || (KERNEL_MEM_ALLOCATION == 0) || \
	defined(__MYTHIC_DEBUG__)
	struct mythic_ipu *mythic_dev;
#endif
	struct mem_book_list *mem_tmp = NULL;
	struct proc_book_list *proc_book = NULL;
	struct buf_list_info *buf_list;
	struct buffer_info_va *va_buffers;
	struct buffer_info_pa *pa_buffers;

	if (!vma)
		return;

	id = (uint64_t)vma->vm_start;
	dma = (struct mythic_dma *)vma->vm_private_data;
	if (!dma) {
		pr_err("Mythic: %s: Invalid dma handle", __func__);
		return;
	}
#if defined(__aarch64__) || (KERNEL_MEM_ALLOCATION == 0) || \
	defined(__MYTHIC_DEBUG__)
	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	dbg_dev_l2("Mythic%d: (%s) Getting process node address",
			mythic_dev->idr, __func__);
	mdma_get_process_node(dma, &proc_book);

	list_for_each_safe(pos, q, &proc_book->mem_book.list) {
		mem_tmp = list_entry(pos, struct mem_book_list, list);
		if (mem_tmp == NULL)
			continue;
		buf_list = &mem_tmp->buf_list;
		if (id != buf_list->id)
			continue;
		va_buffers = mem_tmp->buf_list.va_buffers;
		pa_buffers = mem_tmp->buf_list.pa_buffers;

		buf_count = buf_list->number;
		for (i = 0 ; i < buf_count ; i++) {
			dbg_dev_l3("Mythic%d: (%s) Free dma "
					"coherent memory at "
					"kernel vaddr: 0x%llx",
					mythic_dev->idr, __func__,
					va_buffers[i].vaddr);
#if defined(__x86_64__)
#if (KERNEL_MEM_ALLOCATION == 1)
			kfree((void *)va_buffers[i].vaddr);
#else
			dma_free_coherent(&mythic_dev->pdev->dev,
					pa_buffers[i].bytes,
					(void *)va_buffers[i].vaddr,
					pa_buffers[i].paddr);
#endif
#endif
#if defined(__aarch64__)
			if (mem_tmp->buf_list.alloc_type ==
					MEM_TYPE_MMAP_COHERENT) {
				dma_free_coherent(&mythic_dev->pdev->dev,
						pa_buffers[i].bytes,
						(void *)va_buffers[i].vaddr,
						pa_buffers[i].paddr);
			} else {
				dma_unmap_single(&mythic_dev->pdev->dev,
						pa_buffers[i].paddr,
						pa_buffers[i].bytes,
						DMA_BIDIRECTIONAL);
				kfree((void *)va_buffers[i].vaddr);
			}
#endif
			va_buffers[i].vaddr = (uint64_t)NULL;
			pa_buffers[i].paddr = (uint64_t)NULL;
		}
		kfree(pa_buffers);
		pa_buffers = NULL;
		kfree(va_buffers);
		va_buffers = NULL;
		dbg_dev_l0("Mythic%d: (%s) Free driver mmap "
				"memory at vaddr: 0x%llx",
				mythic_dev->idr,
				__func__, buf_list->id);
		spinlock(&dma->list_slock);
		list_del(pos);
		spinunlock(&dma->list_slock);
		spinlock(&pin_sys_lock);
		mythic_total_pinned_mem -= buf_list->bytes;
		spinunlock(&pin_sys_lock);
		kfree(mem_tmp);
		break;
	}
}

static void vm_open(struct vm_area_struct *vma)
{
	pr_info("%s open method called", __func__);
}

static const struct vm_operations_struct vm_ops = {
	.close = vm_close,
	.open = vm_open,
};

#if defined(__aarch64__)
static int mmap_alloc_coherent_buf(struct mythic_ipu *mythic_dev,
		struct vm_area_struct *vma, int buf_size,
		unsigned long mmap_start, unsigned long mmap_pgoff,
		char **p_vaddr, dma_addr_t *p_dma_addr)
{
	int rv;

	dbg_dev_l3("Mythic%d: %s: mem alloc with dma_alloc_coherent()",
			mythic_dev->idr, __func__);
	*p_vaddr = dma_alloc_coherent(&mythic_dev->pdev->dev,
			buf_size, p_dma_addr, GFP_KERNEL);
	if (!(*p_vaddr)) {
		pr_err("Mythic%d: %s: mem alloc (%d bytes) failed",
				mythic_dev->idr, __func__, buf_size);
		rv = -ENOMEM;
		goto err_out_alloc_coh_arm;
	}
	dbg_dev_l2("Mythic%d: %s: memory allocated",
			mythic_dev->idr, __func__);

	dbg_dev_l2("kernel vaddr: 0x%p, dma_addr: 0x%llx bytes: %d",
			*p_vaddr, *p_dma_addr, buf_size);

	dbg_dev_l3("Mythic%d: %s: calling dma_mmap_coherent()",
			mythic_dev->idr, __func__);
	dbg_dev_l3("kernel vaddr: 0x%p", *p_vaddr);
	rv = dma_mmap_coherent(&mythic_dev->pdev->dev, vma,
			(void *)(*p_vaddr), *p_dma_addr + mmap_pgoff,
			buf_size);
	if (rv < 0) {
		pr_err("Mythic%d: %s: dma_mmap_coherent() fails",
				mythic_dev->idr, __func__);
		pr_err("error code: %d", rv);
		goto err_out_map_coh_arm;
	}
	dbg_dev_l2("Mythic%d: %s: mapping done. kernel vaddr = 0x%p",
			mythic_dev->idr, __func__, *p_vaddr);

	return 0;
err_out_map_coh_arm:
	dma_free_coherent(&mythic_dev->pdev->dev,
			buf_size, *p_vaddr, *p_dma_addr);
err_out_alloc_coh_arm:
	return rv;
}

static int mmap_alloc_cached_buf(struct mythic_ipu *mythic_dev,
		struct vm_area_struct *vma, int buf_size,
		unsigned long mmap_start, unsigned long mmap_pgoff,
		char **p_vaddr, dma_addr_t *p_dma_addr)
{
	int rv;

	dbg_dev_l3("Mythic%d: %s: mem alloc with kmalloc()",
			mythic_dev->idr, __func__);
	*p_vaddr = kmalloc(buf_size, GFP_KERNEL);
	if (!(*p_vaddr)) {
		pr_err("Mythic%d: %s: kmalloc (%d bytes) failed",
				mythic_dev->idr, __func__, buf_size);
		rv = -ENOMEM;
		goto err_out_alloc_cached_arm;
	}
	*p_dma_addr = dma_map_single(&mythic_dev->pdev->dev, *p_vaddr,
			buf_size, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(&mythic_dev->pdev->dev, *p_dma_addr)) {
		pr_err("Mythic%d: %s: dma_map_single (%d bytes) failed",
				mythic_dev->idr, __func__, buf_size);
		rv = -ENOMEM;
		goto err_out_map1_cached_arm;
	}

	dbg_dev_l2("Mythic%d: %s: memory allocated",
			mythic_dev->idr, __func__);
	dbg_dev_l2("kernel vaddr: 0x%p, dma_addr: 0x%llx bytes: %d",
			*p_vaddr, *p_dma_addr, buf_size);

	dbg_dev_l3("Mythic%d: %s: calling remap_pfn_range()",
			mythic_dev->idr, __func__);
	dbg_dev_l3("kernel vaddr: 0x%p", *p_vaddr);


	rv = remap_pfn_range(vma, mmap_start,
			PFN_DOWN(virt_to_phys(*p_vaddr)) + mmap_pgoff,
			buf_size, vma->vm_page_prot);
	if (rv < 0) {
		pr_err("Mythic%d: %s: remap_pfn_range fails. err = %d",
				mythic_dev->idr, __func__, rv);
		goto err_out_map2_cached_arm;
	}

	dbg_dev_l2("Mythic%d: %s: mapping done. kernel vaddr = 0x%p",
			mythic_dev->idr, __func__, *p_vaddr);

	return 0;

err_out_map2_cached_arm:
	dma_unmap_single(&mythic_dev->pdev->dev, *p_dma_addr,
			buf_size, DMA_BIDIRECTIONAL);
err_out_map1_cached_arm:
	kfree(*p_vaddr);
	*p_vaddr = NULL;
err_out_alloc_cached_arm:
	return rv;
}
#endif


/* mmap_alloc_buf
 * @brief: allocate buffer for mmap and map it
 *         there are two versions of this function
 *         one for ARM and one for x86
 * @param mythic_dev: handle to mythic IPU device
 * @param vma: virtual memory area passed by Linux
 * @param va_buffers: buffer to fill virtual address
 * @param pa_buffers: buffer to fill dma address
 * @param alloc_type: allocation type (cached / coherent)
 * @param buf_count: number of chunks to allocate
 * @param chuck_size: size of one chunk (except last one)
 * @param last_buf_size: size of last buffer
 * @return: 0 on success else error code
 */
#if defined(__x86_64__)
static int mmap_alloc_buf(struct mythic_ipu *mythic_dev,
		struct vm_area_struct *vma, struct buffer_info_va *va_buffers,
		struct buffer_info_pa *pa_buffers, int alloc_type,
		int buf_count, int chunk_size, int last_buf_size)
{
	int  i;
	int rv;
	char *vaddr;
	unsigned long mmap_start;
	unsigned long mmap_pgoff;
	dma_addr_t dma_addr;

	mmap_start = vma->vm_start;
	mmap_pgoff = vma->vm_pgoff;
	for (i = 0; i < buf_count; i++) {

		if (i == (buf_count - 1) && last_buf_size != 0)
			chunk_size = last_buf_size;

#if (KERNEL_MEM_ALLOCATION == 1)
		dbg_dev_l3("Mythic%d: %s: mem alloc with kmalloc()",
				mythic_dev->idr, __func__);
		vaddr = kmalloc(chunk_size, GFP_KERNEL);
		if (!vaddr) {
			pr_err("Mythic%d: %s: kmalloc() of %d bytes failed",
					mythic_dev->idr, __func__, chunk_size);
			rv = -ENOMEM;
			goto err_out_mem_alloc_x86;
		}
		dma_addr = virt_to_phys(vaddr);
#endif

#if (KERNEL_MEM_ALLOCATION == 0)
		dbg_dev_l3("Mythic%d: %s: mem alloc with dma_alloc_coherent()",
				mythic_dev->idr, __func__);
		vaddr = dma_alloc_coherent(&mythic_dev->pdev->dev,
				chunk_size,
				&dma_addr, GFP_KERNEL);
		if (!vaddr) {
			pr_err("Mythic%d: %s: mem alloc (%d bytes) failed",
					mythic_dev->idr, __func__, chunk_size);
			rv = -ENOMEM;
			goto err_out_mem_alloc_x86;
		}
#endif

		va_buffers[i].vaddr = (uint64_t)vaddr;
		pa_buffers[i].paddr = (dma_addr_t)dma_addr;
		pa_buffers[i].bytes = (uint32_t)chunk_size;

		dbg_dev_l2("Mythic%d: %s: memory allocated",
				mythic_dev->idr, __func__);
		dbg_dev_l2("kernel vaddr: 0x%llx, dma_addr: 0x%llx bytes: %zu",
				va_buffers[i].vaddr, pa_buffers[i].paddr,
				pa_buffers[i].bytes);

		dbg_dev_l3("Mythic%d: %s: calling remap_pfn_range()",
				mythic_dev->idr, __func__);
		dbg_dev_l3("kernel vaddr: 0x%llx", va_buffers[i].vaddr);

		rv = remap_pfn_range(vma, mmap_start,
				PFN_DOWN(pa_buffers[i].paddr) + mmap_pgoff,
				pa_buffers[i].bytes, vma->vm_page_prot);
		if (rv < 0) {
			pr_err("Mythic%d: %s: remap_pfn_range fails. err = %d",
					mythic_dev->idr, __func__, rv);
			goto err_out_mem_mmap_x86;
		}
		mmap_start += pa_buffers[i].bytes;
		mmap_pgoff = 0;
		dbg_dev_l2("Mythic%d: %s: mapping done. kernel vaddr = 0x%llx",
				mythic_dev->idr, __func__,
				va_buffers[i].vaddr);
	}
	return 0;
err_out_mem_mmap_x86:
err_out_mem_alloc_x86:
	buf_count = i;
	for (i = 0; i < buf_count; i++) {
#if (KERNEL_MEM_ALLOCATION == 1)
		dma_unmap_single(&mythic_dev->pdev->dev, pa_buffers[i].paddr,
				pa_buffers[i].bytes, DMA_BIDIRECTIONAL);
		kfree((void *)va_buffers[i].vaddr);
#endif
#if (KERNEL_MEM_ALLOCATION == 0)
		dma_free_coherent(&mythic_dev->pdev->dev,
				pa_buffers[i].bytes,
				(void *)va_buffers[i].vaddr,
				pa_buffers[i].paddr);
#endif
		va_buffers[i].vaddr = (uint64_t)NULL;
	}
	return rv;
}
#endif

#if defined(__aarch64__)
static int mmap_alloc_buf(struct mythic_ipu *mythic_dev,
		struct vm_area_struct *vma, struct buffer_info_va *va_buffers,
		struct buffer_info_pa *pa_buffers, int alloc_type,
		int buf_count, int chunk_size, int last_buf_size)
{
	int  i;
	int rv;
	char *vaddr;
	unsigned long mmap_start;
	unsigned long mmap_pgoff;
	dma_addr_t dma_addr;

	mmap_start = vma->vm_start;
	mmap_pgoff = vma->vm_pgoff;

	/*
	 * In TX2 and i.MX8 if we use dma_alloc_coherent to allocate coherent
	 * buffers. dma_alloc_coherent can allocate 32 MB or more in a single
	 * call. So there is normally no need to map multiple physically
	 * contiguous buffers to a single contiguous user space memory area.
	 */

	if (alloc_type == MEM_TYPE_MMAP_COHERENT) {
		if (buf_count > 1) {
			pr_err("Mythic%d: %s: invalid count for coherent buf",
					mythic_dev->idr, __func__);
			return -EINVAL;
		}
		rv = mmap_alloc_coherent_buf(mythic_dev, vma, last_buf_size,
				mmap_start, mmap_pgoff, &vaddr, &dma_addr);
		if (rv == 0) {
			va_buffers[0].vaddr = (uint64_t)vaddr;
			pa_buffers[0].paddr = dma_addr;
			pa_buffers[0].bytes = (uint32_t)last_buf_size;
		}
		return rv;
	}
	/* this block is for cached allocation */
	for (i = 0; i < buf_count; i++) {

		if (i == (buf_count - 1) && last_buf_size != 0)
			chunk_size = last_buf_size;

		rv = mmap_alloc_cached_buf(mythic_dev, vma, chunk_size,
				mmap_start, mmap_pgoff, &vaddr, &dma_addr);
		if (rv < 0)
			goto err_out_alloc_buf_arm_cached;

		va_buffers[i].vaddr = (uint64_t)vaddr;
		pa_buffers[i].paddr = dma_addr;
		pa_buffers[i].bytes = (uint32_t)chunk_size;


		mmap_start += pa_buffers[i].bytes;
		mmap_pgoff = 0;
	}
	return 0;
err_out_alloc_buf_arm_cached:
	buf_count = i;
	for (i = 0; i < buf_count; i++) {
		dma_unmap_single(&mythic_dev->pdev->dev, pa_buffers[i].paddr,
				pa_buffers[i].bytes, DMA_BIDIRECTIONAL);
		kfree((void *)va_buffers[i].vaddr);
		va_buffers[i].vaddr = (uint64_t)NULL;
	}
	return rv;
}
#endif

/* mdma_mmap
 * @brief: Allocates contiguous memory
 * @param filp: Handle to struct file pointing mythic_dma structure
 * @param vma: handle to vm_area_struct
 */
int mdma_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int rv = 0;
	uint32_t buf_size;
	int buf_count = 0;
	unsigned long mmap_start;
	uint32_t dma_alloc_size;
	struct mythic_dma *dma;
	struct mythic_ipu *mythic_dev;
	struct buf_list_info *buf_list;
	struct buffer_info_va *va_buffers;
	struct buffer_info_pa *pa_buffers;
	struct mem_book_list *mem_tmp = NULL;
	struct proc_book_list *proc_book = NULL;
	struct sysinfo meminfo;
	unsigned long mem_total, mem_avail, mem_used;
	unsigned long mem_used_percent, pin_mem_used_percent;
	int alloc_type;
	int mmap_mode = CFG_MMAP_MODE_CACHED;

	if (!vma || !filp)
		return -EINVAL;

	dma = (struct mythic_dma *)filp->private_data;
	mythic_dev = container_of(dma, struct mythic_ipu, dma);

	/* mmap would fail if the physical memory consumption on the
	 * host is equal or above a particular percentage of the total
	 * physical memory mentioned in pinMemLimit/mmapMemLimit
	 * sysfs node*/
	si_meminfo(&meminfo);
	mem_total = meminfo.totalram * PAGE_SIZE;
#if KERNEL_VERSION(4, 4, 211) <= LINUX_VERSION_CODE
	mem_avail = si_mem_available() * PAGE_SIZE;
	dbg_dev_l1("Mythic%d: (%s) mem_avail (si_mem_available): %ld\n",
			mythic_dev->idr, __func__, mem_avail);
#else
        mem_avail = meminfo.freeram * PAGE_SIZE;
	dbg_dev_l1("Mythic%d: (%s) mem_avail (freeram): %ld\n",
			mythic_dev->idr, __func__, mem_avail);
#endif
	mem_used = mem_total - mem_avail;
	mem_used_percent = (mem_used * 100) / mem_total;
	spinlock(&pin_sys_lock);
	pin_mem_used_percent = (mythic_total_pinned_mem * 100) / mem_total;
	spinunlock(&pin_sys_lock);
	dbg_dev_l1("Mythic%d: (%s) mem_used %ld\n", mythic_dev->idr, __func__, mem_used);
	dbg_dev_l0("Mythic%d: (%s) mem_used_percent: %ld,  mythic_mem_uplimit: %d\n",
			mythic_dev->idr, __func__, mem_used_percent, mythic_mem_uplimit);
	dbg_dev_l0("Mythic%d: (%s) pin_mem_used_percent: %ld, mythic_pin_mem_uplimit: %d\n",
			mythic_dev->idr, __func__, pin_mem_used_percent, mythic_pin_mem_uplimit);
	if (mem_used_percent >= mythic_mem_uplimit) {
		pr_err("Mythic%d: Total memory usage is greater "
				"than the set limit %d %%",
				mythic_dev->idr, mythic_mem_uplimit);
		return -ENOSPC;
	}
	if (pin_mem_used_percent >= mythic_pin_mem_uplimit) {
		pr_err("Mythic%d: Total pinned memory usage is greater "
				"than the set limit %d %%",
				mythic_dev->idr, mythic_pin_mem_uplimit);
		return -ENOSPC;
	}

	buf_size = vma->vm_end - vma->vm_start;
	mmap_start = vma->vm_start;
	if (buf_size == 0) {
		pr_err("Mythic%d: Driver mmap buffer size requested is "
				"%d bytes", mythic_dev->idr, buf_size);
		return -EINVAL;
	}

	vma->vm_ops = &vm_ops;
	vma->vm_private_data = (void *)dma;

	mdma_get_process_node(dma, &proc_book);

	mdma_get_mmap_mode(proc_book, &mmap_mode);
	if (mmap_mode == CFG_MMAP_MODE_CACHED)
		alloc_type = MEM_TYPE_MMAP_CACHED;
	else
		alloc_type = MEM_TYPE_MMAP_COHERENT;

	dma_alloc_size = get_max_mem_chunk_size(alloc_type);
	while (buf_size > 0) {
		buf_count++;
		if (buf_size >= dma_alloc_size)
			buf_size -= dma_alloc_size;
		else
			break;
	}

	mem_tmp = kzalloc(sizeof(struct mem_book_list),
			GFP_KERNEL);
	if (mem_tmp == NULL) {
		pr_err("Mythic%d: Allocation of memory node in book-keep "
				"list failed", mythic_dev->idr);
		rv = -ENOMEM;
		goto err_out_tmp_alloc;
	}

	pa_buffers = kmalloc(sizeof(struct buffer_info_pa)*
			buf_count, GFP_KERNEL);
	if (pa_buffers == NULL) {
		pr_err("Mythic%d: Buffer allocation for paddr "
				"failed", mythic_dev->idr);
		rv = -ENOMEM;
		goto err_out_pa_alloc;
	}
	va_buffers = kmalloc(sizeof(struct buffer_info_va)*
			buf_count, GFP_KERNEL);
	if (va_buffers == NULL) {
		pr_err("Mythic%d: Buffer allocation for kvaddr "
				"failed", mythic_dev->idr);
		rv = -ENOMEM;
		goto err_out_va_alloc;
	}

	buf_list = &mem_tmp->buf_list;
	mem_tmp->buf_list.va_buffers = va_buffers;
	mem_tmp->buf_list.pa_buffers = pa_buffers;

	buf_list->id = (uint64_t)mmap_start;
	buf_list->bytes = vma->vm_end - vma->vm_start;
	buf_list->alloc_type = alloc_type;

	rv = mmap_alloc_buf(mythic_dev, vma, va_buffers, pa_buffers,
			alloc_type, buf_count, dma_alloc_size, buf_size);

	if (rv < 0)
		goto err_out_mmap_alloc;

	buf_list->number = buf_count;
	spinlock(&dma->list_slock);
	/* Adding memory node to the memory book-keeping list */
	list_add(&mem_tmp->list, &proc_book->mem_book.list);
	spinunlock(&dma->list_slock);
	spinlock(&pin_sys_lock);
	mythic_total_pinned_mem += buf_list->bytes;
	spinunlock(&pin_sys_lock);
	dbg_dev_l0("Mythic%d: (%s) Driver mmap memory at vaddr: 0x%llx",
			mythic_dev->idr, __func__, buf_list->id);
	dbg_dev_l2("Mythic%d: (%s) Added memory node in proc_book at "
			"0x%p\n", mythic_dev->idr, __func__, proc_book);
	return 0;


err_out_mmap_alloc:
	kfree((void *)va_buffers);
	va_buffers = NULL;
err_out_va_alloc:
	kfree((void *)pa_buffers);
	pa_buffers = NULL;
err_out_pa_alloc:
	kfree((void *)mem_tmp);
err_out_tmp_alloc:
	return rv;
}

static int map_single_bar(struct mythic_dma *dma,
		struct pci_dev *dev, int idx)
{
	resource_size_t bar_start;
	resource_size_t bar_len;
	resource_size_t map_len;
	struct mythic_ipu *mythic_dev;

	if (!dma || !dev)
		return -EINVAL;

	bar_start = pci_resource_start(dev, idx);
	bar_len = pci_resource_len(dev, idx);
	map_len = bar_len;
	dma->dma_bar[idx] = NULL;
	mythic_dev = container_of(dma, struct mythic_ipu, dma);

	/* do not map BARs with length 0. Note that start MAY be 0! */
	if (!bar_len) {
		dbg_dev_l3("Mythic%d: BAR length is %d",
				mythic_dev->idr, (int)bar_len);
		return 0;
	}

	/* BAR size exceeds maximum desired mapping? */
	if (bar_len > INT_MAX) {
		pr_info("Mythic%d: Limit BAR %d mapping "
				"from %llu to %d bytes",
				mythic_dev->idr, idx,
				(uint64_t)bar_len, INT_MAX);
		map_len = (resource_size_t)INT_MAX;
	}

	/* map the full device memory or IO region into
	 * kernel virtual address space
	 */
	pr_info("Mythic%d: BAR%d: %llu bytes to be mapped",
			mythic_dev->idr,
			idx, (uint64_t)map_len);
#if WRITE_COMBINED_ENABLED
	pr_info("Mythic%d: BAR ioremap: write combined",
			mythic_dev->idr);
	dma->dma_bar[idx] = pci_ioremap_wc_bar(dev, idx);
#else
	pr_info("Mythic%d: BAR ioremap: not write combined",
			mythic_dev->idr);
	dma->dma_bar[idx] = pci_ioremap_bar(dev, idx);
#endif
	mythic_dev->bar[idx] = dma->dma_bar[idx];

	if (!dma->dma_bar[idx]) {
		pr_err("Mythic%d: Could not map BAR %d",
				mythic_dev->idr, idx);
		return -EIO;
	}

	pr_info("Mythic%d: BAR%d at 0x%llx mapped at "
			"0x%llx, length=%llu(/%llu)",
			mythic_dev->idr, idx,
			(uint64_t)bar_start,
			(uint64_t)dma->dma_bar[idx],
			(uint64_t)map_len, (uint64_t)bar_len);

	return (int)map_len;
}

/* set_dma_mask
 * @brief: Sets the dma mask to the highest supported size.
 * This function is added for linux dma subsystem compliance.
 * request, relaxed ordering, map bars and dma mask.
 * @param pdev: Handle to pci_dev structure
 * @return: error code
 */
static int set_dma_mask(struct pci_dev **pdev)
{
	struct mythic_ipu *mythic_dev;

	if (!pdev)
		return -EINVAL;

	mythic_dev = container_of(pdev, struct mythic_ipu, pdev);
	/* 64-bit addressing capability for DMA? */
	if (!pci_set_dma_mask(*pdev, DMA_BIT_MASK(64))) {
		/* use 64-bit DMA */
		pr_info("Mythic%d: Using a 64-bit DMA mask",
				mythic_dev->idr);
		pci_set_consistent_dma_mask(*pdev, DMA_BIT_MASK(64));
	} else if (!pci_set_dma_mask(*pdev, DMA_BIT_MASK(32))) {
		pr_info("Mythic%d: Could not set 64-bit DMA mask",
				mythic_dev->idr);
		pci_set_consistent_dma_mask(*pdev, DMA_BIT_MASK(32));
		/* use 32-bit DMA */
		pr_info("Mythic%d: Using a 32-bit DMA mask",
				mythic_dev->idr);
	} else {
		pr_err("Mythic%d: No suitable DMA possible",
				mythic_dev->idr);
		return -EINVAL;
	}
	return 0;
}

static int mdma_map_bar(struct mythic_dma *dma, struct pci_dev *pdev)
{
	resource_size_t bar_len;
	struct mythic_ipu *mythic_dev;

	if (!dma || !pdev)
		return -EINVAL;

	mythic_dev = container_of(dma, struct mythic_ipu, dma);
	bar_len = map_single_bar(dma, pdev, BAR_0);
	if (bar_len < 0)
		pr_err("Mythic%d: DMA MAP bar %d failed %d",
				mythic_dev->idr,
				BAR_0, (int)bar_len);
	return bar_len;
}

static void pci_relaxed_ordering(struct pci_dev **pdev, int relax_flag)
{
#if KERNEL_VERSION(3, 5, 0) >= LINUX_VERSION_CODE
	struct mythic_ipu *mythic_dev;
#endif

	if (!pdev)
		return;
#if KERNEL_VERSION(3, 5, 0) >= LINUX_VERSION_CODE
	mythic_dev = container_of(pdev, struct mythic_ipu, pdev);
#endif

#if KERNEL_VERSION(3, 5, 0) < LINUX_VERSION_CODE
	if (relax_flag == 0)
		pcie_capability_clear_word(*pdev, PCI_EXP_DEVCTL,
				PCI_EXP_DEVCTL_RELAX_EN);
	else
		pcie_capability_set_word(*pdev, PCI_EXP_DEVCTL,
				PCI_EXP_DEVCTL_RELAX_EN);
#else
	u16 v;
	int pos;

	pos = pci_pcie_cap(*pdev);
	if (pos > 0) {
		pci_read_config_word(*pdev, pos + PCI_EXP_DEVCTL, &v);
		pr_info("Mythic%d: DevCtl: Relaxed ordering: 0x%x",
				mythic_dev->idr, v);
		if (relax_flag == 0)
			v &= ~PCI_EXP_DEVCTL_RELAX_EN;
		else
			v |= PCI_EXP_DEVCTL_RELAX_EN;
		pci_write_config_word(*pdev, pos + PCI_EXP_DEVCTL, v);
		v = 0;
		pci_read_config_word(*pdev, pos + PCI_EXP_DEVCTL, &v);
		pr_info("Mythic%d: DevCtl: Relaxed ordering: 0x%x",
				mythic_dev->idr, v);
	}
#endif
}

static uint16_t pcie_get_devcap_size(uint16_t value)
{
	switch (value) {
	case 0: return 128;
	case 1: return 256;
	case 2: return 512;
	case 3: return 1024;
	case 4: return 2048;
	case 5: return 4096;
	default: return -1;
	}
}

static void pci_cap_reg_console_dump(struct pci_dev **pdev)
{
	u16 cap;
	struct mythic_ipu *mythic_dev;

	if (!pdev)
		return;
	mythic_dev = container_of(pdev, struct mythic_ipu, pdev);

#if KERNEL_VERSION(3, 5, 0) <= LINUX_VERSION_CODE
	pcie_capability_read_word(*pdev, PCI_EXP_DEVCAP, &cap);
	pr_info("Mythic%d: DevCap: MaxPayload %d bytes",
			mythic_dev->idr,
			pcie_get_devcap_size(cap &
				PCI_EXP_DEVCAP_PAYLOAD));
	pcie_capability_read_word(*pdev, PCI_EXP_DEVCTL, &cap);
	pr_info("Mythic%d: DevCtl: MaxPayload %d bytes, "
			"MaxReadReq %d bytes",
			mythic_dev->idr,
			pcie_get_devcap_size((cap &
					PCI_EXP_DEVCTL_PAYLOAD) >> 5),
			pcie_get_devcap_size((cap &
					PCI_EXP_DEVCTL_READRQ) >> 12));
#else
	int pos;

	pos = pci_pcie_cap(*pdev);
	if (pos > 0) {
		pci_read_config_word(*pdev, pos +
				PCI_EXP_DEVCAP, &cap);
		pr_info("Mythic%d: DevCap: MaxPayload %d bytes",
				mythic_dev->idr,
				pcie_get_devcap_size(cap &
					PCI_EXP_DEVCAP_PAYLOAD));
		pci_read_config_word(*pdev, pos +
				PCI_EXP_DEVCTL, &cap);
		pr_info("Mythic%d: DevCtl: MaxPayload %d bytes, "
				"MaxReadReq %d bytes",
				mythic_dev->idr,
				pcie_get_devcap_size((cap &
						PCI_EXP_DEVCTL_PAYLOAD) >> 5),
				pcie_get_devcap_size((cap &
						PCI_EXP_DEVCTL_READRQ) >> 12));
	}
#endif
}

/* mdma_init
 * @brief: Initialize pcie device for dma transfer. This sets pcie read
 * request, relaxed ordering, map bars and dma mask.
 * @param dev: Handle to device structure
 * @return: error code
 */
int mdma_init(void *dev)
{
	printk("inside mdma_init\n");
	int rv;
	struct mythic_ipu *mythic_dev;

	if (!dev)
		return -EINVAL;

	mythic_dev = (struct mythic_ipu *)dev;
	mythic_dev->dma.channels = MYTHIC_DMA_CHANNELS;
	mythic_dev->dma.dma_handle = mythic_dev->pdev;

	rv = pcie_set_readrq(mythic_dev->pdev, PCI_READ_REQ_512K);
	if (rv)
		pr_err("Mythic%d: device %s, maximum read request setting"
				" error: %d", mythic_dev->idr,
				dev_name(&mythic_dev->pdev->dev), rv);

	pci_relaxed_ordering(&mythic_dev->pdev, 0);

	rv = mdma_map_bar(&mythic_dev->dma, mythic_dev->pdev);
	if (rv < 0) {
		pr_err("Mythic%d: BAR mapping failed", mythic_dev->idr);
		return rv;
	}
	else
		printk("bar mapping success\n");

	rv = set_dma_mask(&mythic_dev->pdev);
	if (rv)
		pr_err("Mythic%d: DMA mask set failed", mythic_dev->idr);

	pci_cap_reg_console_dump(&mythic_dev->pdev);

	sema_init(&mythic_dev->dev_lock, 1);
	mutex_init(&mythic_dev->proc_lock.sema_lock);

	mutex_lock(&mythic_dev->proc_lock.sema_lock);
	mythic_dev->proc_lock.sema_max_count =
		mythic_dev->proc_lock.sema_count =
		MYTHIC_IPU_SEMLOCK_COUNT;

	if (mythic_dev->proc_lock.sema_max_count ==
			mythic_dev->proc_lock.sema_count) {
		sema_init(&mythic_dev->proc_lock.p_lock,
				mythic_dev->proc_lock.sema_max_count);
		mutex_unlock(&mythic_dev->proc_lock.sema_lock);
		pr_info("Mythic%d: IPU max process count: %d",
				mythic_dev->idr,
				mythic_dev->proc_lock.sema_max_count);
	} else {
		mutex_unlock(&mythic_dev->proc_lock.sema_lock);
	}
	return 0;
}

EXPORT_SYMBOL(mdma_init);

inline void write_mmio(u32 value, void *iomem, int flag)
{
	u8 value_u8 = value & 0xFF;

	if (flag == MMIO_BYTE_MODE)
		writeb(value_u8, iomem);
	else
		writel(value, iomem);
}

inline uint32_t read_mmio(void *iomem, int flag)
{
	if (flag == MMIO_BYTE_MODE)
		return readb(iomem);
	else
		return readl(iomem);
}

/* mdma_write_mmio
 * @brief: Writes to BAR0 offest from the specified buffer
 * in MBAR_BUF structure
 * @param dma: Handle to mythic_dma structure
 * @param mbar_buf: Holds the buffer address, data size
 * @return: error code
 */
int mdma_write_mmio(struct mythic_dma *dma, MBAR_BUF *mbar_buf)
{
#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 5
	uint32_t i;
	struct mythic_ipu *mythic_dev;
#endif
#if !MMIO_RW_MEMCPY
	uint8_t *arr;
#ifndef __MYTHIC_DEBUG__
	uint32_t i;
#endif
#endif
	char *reg;
	uint32_t bytes;
	unsigned long flags;

	if (!dma || !mbar_buf || !mbar_buf->bytes)
		return -EINVAL;

#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 5
	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	dma->bar = dma->dma_bar[BAR_0];
	((mbar_buf->bytes % WORD_NBYTES) == 0) ?
		(bytes = mbar_buf->bytes/WORD_NBYTES) :
		(bytes = mbar_buf->bytes/WORD_NBYTES) + 1;

#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 5
	for (i = 0; i < bytes ; i++) {
		reg = dma->bar + mbar_buf->offset +
			i*sizeof(uint32_t);
		dbg_dev_l5("Mythic%d: (%s) reg:0x%llx, "
				"mbar_buf->arr[%d]:0x%x",
				mythic_dev->idr, __func__,
				(uint64_t)reg,
				i, mbar_buf->arr[i]);
	}
#endif

	spinlock_irqsave(&dma->mdma_mmio_lock, flags);
#if MMIO_RW_MEMCPY
	reg = dma->bar + mbar_buf->offset;
	memcpy(reg, mbar_buf->arr, mbar_buf->bytes);
	readb(reg+ (mbar_buf->bytes)*sizeof(uint8_t));
#else
	if ((mbar_buf->bytes % WORD_NBYTES) != 0) {
		arr = (uint8_t *)mbar_buf->arr;
		for (i = 0; i < mbar_buf->bytes; i++) {
			reg = dma->bar + mbar_buf->offset +
				i*sizeof(uint8_t);
			write_mmio(arr[i], reg, MMIO_BYTE_MODE);
		}
	} else {
		for (i = 0; i < bytes; i++) {
			reg = dma->bar + mbar_buf->offset +
				i*sizeof(uint32_t);
			write_mmio(cpu_to_le32(mbar_buf->arr[i]),
					reg, MMIO_WORD_MODE);
		}
	}
#endif
#if KERNEL_VERSION(5, 2, 0) > LINUX_VERSION_CODE
	mmiowb();
#endif
	mb();
	spinunlock_irqrestore(&dma->mdma_mmio_lock, flags);
	return 0;
}

/* mdma_read_mmio
 * @brief: Reads the BAR0 offest to the specified buffer in MBAR_BUF
 * structure
 * @param dma: Handle to mythic_dma structure
 * @param mbar_buf: Holds the buffer address, data size
 * @return: error code
 */
int mdma_read_mmio(struct mythic_dma *dma, MBAR_BUF *mbar_buf)
{
#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 5
	uint32_t i;
	struct mythic_ipu *mythic_dev;
#endif
#if !MMIO_RW_MEMCPY
	uint8_t *arr;
#ifndef __MYTHIC_DEBUG__
	uint32_t i;
#endif
#endif
	char *reg;
#if KERNEL_VERSION(4, 0, 0) <= LINUX_VERSION_CODE
	unsigned long flags;
#endif
	uint32_t bytes;

	if (!dma || !mbar_buf || !mbar_buf->bytes)
		return -EINVAL;

#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 5
	mythic_dev = container_of(dma, struct mythic_ipu, dma);
#endif
	dma->bar = dma->dma_bar[BAR_0];
	((mbar_buf->bytes % WORD_NBYTES) == 0) ?
		(bytes = mbar_buf->bytes/WORD_NBYTES) :
		(bytes = mbar_buf->bytes/WORD_NBYTES) + 1;

	spinlock_irqsave(&dma->mdma_mmio_lock, flags);
#if MMIO_RW_MEMCPY
	reg = dma->bar + mbar_buf->offset;
	memcpy(mbar_buf->arr, reg, mbar_buf->bytes);
#else
	if ((mbar_buf->bytes % WORD_NBYTES) != 0) {
		arr = (uint8_t *)mbar_buf->arr;
		for (i = 0; i < mbar_buf->bytes; i++) {
			reg = dma->bar + mbar_buf->offset +
				i*sizeof(uint8_t);
			arr[i] = read_mmio(reg, MMIO_BYTE_MODE);
		}
	} else {
		for (i = 0; i < bytes ; i++) {
			reg = dma->bar + mbar_buf->offset +
				i*sizeof(uint32_t);
			mbar_buf->arr[i] = read_mmio(reg, MMIO_WORD_MODE);
		}
	}
#endif
	spinunlock_irqrestore(&dma->mdma_mmio_lock, flags);
#if defined(__MYTHIC_DEBUG__) && MYTHIC_DEBUG_LEVEL >= 5
	for (i = 0; i < bytes ; i++) {
		reg = dma->bar + mbar_buf->offset +
			i*sizeof(uint32_t);
		dbg_dev_l5("Mythic%d: (%s) reg:0x%llx, "
				"mbar_buf->arr[%d]:0x%x",
				mythic_dev->idr, __func__,
				(uint64_t)reg,
				i, mbar_buf->arr[i]);
	}
#endif
	return 0;
}
