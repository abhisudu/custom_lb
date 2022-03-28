/* SPDX-License-Identifier: GPL-2.0 */
/*
 * @file    mythic_ipu_api.h
 * @author  Flemin Jose <flemin.jose@ignitarium.com>
 *
 * Copyright (C) Mythic AI, Inc.
 */

#ifndef  __MYTHIC_IPU_API_H__
#define __MYTHIC_IPU_API_H__

typedef struct {
        uint64_t   vaddr;       /* user space address */
        size_t     bytes;       /* bytes pointed by vaddr */
} MUSER_BUF;

typedef MUSER_BUF PIN_STRUCT;

typedef struct {
        uint8_t    forced;      /* forced unpin for all, or not */
        MUSER_BUF  buf;         /* buf to unpin */
} UNPIN_STRUCT;

enum sync_direction { MYTHIC_SYNC_FOR_DEVICE, MYTHIC_SYNC_FOR_CPU };
typedef struct {
        uint8_t    sync_dir;    /* 0 if sync for device
                                 * 1 if sync for cpu */
        uint64_t   vaddr;       /* user space address */
} SYNC_STRUCT;

typedef struct {
        uint64_t   paddr;       /* physical start address of frame  */
        size_t     bytes;       /* bytes in this frame */
} buffer;

typedef struct {
        uint8_t    mmap;        /* don't care, to be removed*/
        MUSER_BUF  buf;         /* user addr and size allocated
                                 * for mmap/pinned buffer */
} NUMBUF_STRUCT;

typedef struct {
        MUSER_BUF  buf;         /* user addr and size allocated
                                 * for mmap/pinned buffer */
        uint32_t   number;      /* number of elements in array below */
        buffer     *buffers;
} MBUF_LIST;

typedef struct {
        uint32_t   offset;      /* offset in bar0 */
        uint32_t   bytes;       /* bytes to read/write */
        uint32_t   *arr;        /* uint32_t array of items bytes/4
                                 * to read/write */
} MBAR_BUF;

typedef buffer phy_info;

#define MYTHIC_IOC_BUF_MODE_MAX         0 /* This mode sends the physical address
                                             of contiguous chunks without
                                             splitting down to 4KB chunks */
#define MYTHIC_IOC_BUF_MODE_4KB         1 /* This mode sends the physical address
                                             of 4KB chunks */
/* options for SET_MMAP_MODE IOCTL */
#define MYTHIC_MMAP_MODE_CACHED         0x0 /* Allocate cached memory */
#define MYTHIC_MMAP_MODE_COHERENT       0x1 /* Allocate coherent memory */
#define MDMA_NUM                        10
#define MYTHIC_IOC_MAGIC                'M'
#define MYTHIC_IOC_GET_PROC_COUNT       _IOR(MYTHIC_IOC_MAGIC, 1, int32_t)
#define MYTHIC_IOC_SET_PROC_COUNT       _IOW(MYTHIC_IOC_MAGIC, 2, int32_t)
#define MYTHIC_IOC_GET_CLEANUP_TIMER_PERIOD \
                                        _IOW(MYTHIC_IOC_MAGIC, 3, int32_t)
#define MYTHIC_IOC_SET_CLEANUP_TIMER_PERIOD \
                                        _IOW(MYTHIC_IOC_MAGIC, 4, int32_t)

#define MYTHIC_IOC_PIN_USER     _IOW(MYTHIC_IOC_MAGIC, \
                                        MDMA_NUM, PIN_STRUCT)
#define MYTHIC_IOC_UNPIN_USER   _IOW(MYTHIC_IOC_MAGIC, \
                                        MDMA_NUM+1, UNPIN_STRUCT)
#define MYTHIC_IOC_NUMBUF       _IOW(MYTHIC_IOC_MAGIC,  MDMA_NUM+2, \
                                        NUMBUF_STRUCT)
#define MYTHIC_IOC_GETBUF_PIN   _IOWR(MYTHIC_IOC_MAGIC, MDMA_NUM+3, \
                                        MBUF_LIST)
#define MYTHIC_IOC_GETBUF_MMAP  _IOWR(MYTHIC_IOC_MAGIC, MDMA_NUM+4, \
                                        MBUF_LIST)
#define MYTHIC_IOC_WRITE_MMIO   _IOW(MYTHIC_IOC_MAGIC,  MDMA_NUM+5, \
                                        MBAR_BUF)
#define MYTHIC_IOC_READ_MMIO    _IOWR(MYTHIC_IOC_MAGIC, MDMA_NUM+6, \
                                        MBAR_BUF)
#define MYTHIC_IOC_SYNC_BUF     _IOW(MYTHIC_IOC_MAGIC,  MDMA_NUM+9, \
                                        SYNC_STRUCT)
#define MYTHIC_IOC_GET_GETBUF_MODE      _IOR(MYTHIC_IOC_MAGIC, \
                                                MDMA_NUM+10, int)
#define MYTHIC_IOC_SET_GETBUF_MODE      _IOW(MYTHIC_IOC_MAGIC, \
                                                MDMA_NUM+11, int)
#define MYTHIC_IOC_SET_MMAP_MODE        _IOW(MYTHIC_IOC_MAGIC, \
                                                MDMA_NUM + 12, uint32_t)
#define MYTHIC_IOC_GET_MMAP_MODE        _IOW(MYTHIC_IOC_MAGIC, \
                                                MDMA_NUM + 13, uint32_t)

/*
 * TODO-NOTE :
 * 1. MYTHIC_IOC_GETBUF_PIN and MYTHIC_IOC_GETBUF_MMAP performs same
 * operation. So, MYTHIC_IOC_GETBUF_PIN has to rename to MYTHIC_IOC_GETBUF
 * and MYTHIC_IOC_GETBUF_MMAP has to be removed.
 * 2. Give sequential number to the ioctl commands that comes after
 * MYTHIC_IOC_GETBUF_PIN ioctl.
 */

#endif /* __MYTHIC_IPU_API_H__ */

