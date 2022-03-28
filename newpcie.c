#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/netlink.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/aer.h>
#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/io.h>
#include <linux/mm.h>
#include "mythic.h"

#if KERNEL_VERSION(4, 9, 0) > LINUX_VERSION_CODE
#include <linux/interrupt.h>
#endif

#define MYTHIC_DRIVER_VERSION           "1.0.0"

#define dev_to_mythic_dev(_dev)         pci_get_drvdata(to_pci_dev(_dev))
#define BAR_MASK_NIBBLE                 0x0000000F
//#define DRV_MODULE_NAME                 "mythic_new"
//#define MYTHIC_VENDOR_ID                0x1e53
//#define MYTHIC_DEVICE_ID                0x9024

//MODULE_LICENSE("GPL");
extern int mdma_init(void *dev);

static DEFINE_MUTEX(core_lock);
static DEFINE_IDR(mythic_idr);
static struct mythic_ipu *mythic_dev;
/*enum pci_bar_no {
        BAR_0,
        BAR_1,
        BAR_2,
        BAR_3,
        BAR_4,
        BAR_5,
};

struct mythic_dma {
        int major;
        int minor;
        dev_t devno;
        struct cdev cdev;
        int channels;           //  Total dma channels
        struct class *device_class;
        void *dma_handle;       // Points to the PCI device
        void __iomem *bar;
        void __iomem *dma_bar[4];
};

struct mythic_ipu {
        unsigned int idr;
        struct pci_dev *pdev;
        void __iomem *bar[6];
        struct cdev cdev;
        dev_t devno;
        char devname[15];
        struct mythic_dma dma;
};*/

typedef struct {
    uint32_t   bytes;       // size of data in bytes
    uint8_t    type;        // descriptor type
    uint8_t    cmd;         // command bits
    uint16_t   id_lo;       // descriptor id bits 0-15
    uint32_t   addr_lo;     // physical address bits 0-31
    uint16_t   addr_hi;     // physical address bits 32-47
    uint16_t   id_hi;       // descriptor id bits 16-31
    uint32_t   cmpl_error;  // error dword from completion bytes
    uint32_t   cmpl_time;   // time of completion in NP local units
    uint32_t   desc_count;  // count of completed descs till now
    uint32_t   rsvd;        // not being used for now
} __attribute__((packed)) MDMA_DATA_DESC;

struct class *ipu_dma_class;

int test_check(void)
{
	printk("INSIDE PCI DRIVER\n");
	return 0;
}
EXPORT_SYMBOL(test_check);

inline uint32_t read_mmio(void *iomem, int flag)
{
         //if (flag == MMIO_BYTE_MODE)
                 //return readb(iomem);
         //else
	return readl(iomem);
 }

uint32_t mythic_dev_read(uint32_t *buf,size_t len, uint32_t offset)
{

        //struct mythic_ipu *mythic_dev;
/*	dma = (struct mythic_dma *)filp->private_data;
        mythic_dev = container_of(dma, struct mythic_ipu, dma);*/
        char *reg;
	uint32_t *buf1;
//	uint32_t *arr = 0;
//	uint32_t bytes, i;
	printk("offset value is %x\n",offset);
        //dma->bar = dma->dma_bar[BAR_0];
        mythic_dev->dma.bar = mythic_dev->dma.dma_bar[BAR_0];
	printk("value of dma_bar is %p\n", mythic_dev->dma.bar);
	reg = mythic_dev->dma.bar + offset;
	printk("register address is %s\n",reg);
//	printk("reg value is 0x%x\n",(*reg));
	buf1 = kzalloc(len, GFP_KERNEL);
        memcpy((void *)buf1, (void *)reg, len);
	printk("reg value is 0x%x\n",(*buf1));

/*	printk("length is %ld\n",len);
	 ((len % WORD_NBYTES) == 0) ?
                 (bytes = len/WORD_NBYTES) :
                 (bytes = len/WORD_NBYTES) + 1;

	for (i = 0; i < bytes ; i++) {
        	reg = mythic_dev->dma.bar + offset + i*sizeof(uint32_t);
//                arr[i] = read_mmio(reg, MMIO_WORD_MODE);
//		printk("register value is %x", arr[i]);
	}*/


        return (*buf1);
}
EXPORT_SYMBOL(mythic_dev_read);

int mythic_dev_write(uint32_t *buf1, size_t len, uint32_t offset)
{
        //struct mythic_dma *dma;
        /*struct pcie_ipu *mythic_dev;
        dma = (struct mythic_dma *)filp->private_data;
        mythic_dev = container_of(dma, struct mythic_ipu, dma);*/

	char *reg;
	uint32_t *buf2;
	printk("offset value is %x\n",offset);
        mythic_dev->dma.bar = mythic_dev->dma.dma_bar[BAR_0];
        reg = mythic_dev->dma.bar + offset;
        memcpy((void *)reg, (void *)buf1, len);
	//printk("input buffer value is %llx\n",(*((uint64_t *)buf1)));

//	buf2 = kzalloc(len, GFP_KERNEL);
 //       memcpy((void *)buf2, (void *)reg, len);
//	printk("reg value is 0x%x\n",(*buf2));
//	printk("reg value is %x\n",(*buf2 ));
//	printk("reg value is %x\n",(*(buf2 + 1)));

        return 0;
}
EXPORT_SYMBOL(mythic_dev_write);

MDMA_DATA_DESC *mythic_set_desc(uint64_t *data, uint32_t size, uint32_t desc_id, uint8_t dtype, uint8_t cmd)
{
        MDMA_DATA_DESC *d;
	d = kzalloc(sizeof(*d), GFP_KERNEL);
        uint64_t paddr;
	printk("virtual address is %p\n", (void *)data);

        paddr = pci_map_single(mythic_dev->pdev, data, size, DMA_BIDIRECTIONAL);
	printk("physical address is %llx\n", paddr);

        d->bytes = size;
        d->type = dtype;  //write or read
	printk("desc type is %x\n", dtype);
        d->id_lo = desc_id & 0xFFFF; d->id_hi = (desc_id >> 16) & 0xFFFF;
        d->addr_lo = (uint32_t) (paddr & 0xFFFFFFFFLL);     // bits 0-31
	printk("lower address is %x\n",d->addr_lo);
        d->addr_hi = (uint16_t) ((paddr >> 32) & 0xFFFFLL); // bits 32-47
	printk("higher address is %x\n",d->addr_hi);
        d->cmd = cmd; // remove undefined bits from this register

        return d;

}
EXPORT_SYMBOL(mythic_set_desc);

static void unmap_bars(struct pci_dev *pdev, struct mythic_ipu *mythic_dev)
 {
          enum pci_bar_no bar;

          for (bar = BAR_0; bar <= BAR_5; bar++) {
                  if (mythic_dev->bar[bar]) {
                          pci_iounmap(pdev, mythic_dev->bar[bar]);
                          mythic_dev->bar[bar] = NULL;
                  }
          }
  }

static int mythic_ipu_probe(struct pci_dev *pdev,
                const struct pci_device_id *pdev_id)
{
        printk("Inside pci probe function\n");
	int rv = -EIO;
  //      struct mythic_ipu *mythic_dev;
        struct device *dev = &pdev->dev;
        uint16_t value;

        if (pci_is_bridge(pdev)) {
                dev_err(dev, "Mythic : PCi device is a bridge\n");
                rv = -ENODEV;
                   return rv;
        }

        mythic_dev = devm_kzalloc(dev, sizeof(*mythic_dev), GFP_KERNEL);
        if (mythic_dev == NULL) {
                dev_err(dev, "Mythic%d: Failed to allocate memory for"
                                "mythic device\n", mythic_dev->idr);
                rv = -ENOMEM;
                return rv;
        }

        mythic_dev->pdev = pdev;

        mutex_lock(&core_lock);
        mythic_dev->idr = idr_alloc(&mythic_idr, mythic_dev, 0, 0, GFP_KERNEL);
        mutex_unlock(&core_lock);

        snprintf(mythic_dev->devname, sizeof(mythic_dev->devname),
                        "mythic%d", mythic_dev->idr);


        rv = pci_enable_device(pdev);
        if (rv) {
                dev_err(dev, "Mythic%d: Cannot enable PCI device\n",
                                mythic_dev->idr);

        }

        pci_set_master(pdev);
          /* AER (Advanced Error Reporting) hooks */
        pci_enable_pcie_error_reporting(pdev);

        rv = pci_request_regions(pdev, DRV_MODULE_NAME);
        if (rv) {
                dev_err(dev, "Mythic%d: Cannot request PCI regions\n",
                                mythic_dev->idr);
                goto out_pci_disable;
        }
        mythic_dev->dma.device_class = ipu_dma_class;
	rv = mdma_init(mythic_dev);
        if (rv < 0) {
        	dev_err(dev, "Mythic%d: Unable to create mythic DMA device ioctls\n",
                                  mythic_dev->idr);
                  goto out_pci_request_regions;
          }

        pci_set_drvdata(pdev, mythic_dev);

        rv = pci_read_config_word(pdev, PCI_VENDOR_ID, &value);
        if (rv < 0)
                dev_err(dev, "Mythic%d: Unable to read PCI vendor id\n",
                                mythic_dev->idr);
        dev_info(dev, "Mythic%d: Vendor ID: 0x%x", mythic_dev->idr, value);

        rv = pci_read_config_word(pdev, PCI_DEVICE_ID, &value);
        if (rv < 0)
                dev_err(dev, "Mythic%d: Unable to read PCI device id\n",
                                mythic_dev->idr);
        dev_info(dev, "Mythic%d: Device ID: 0x%x", mythic_dev->idr, value);

        rv = pci_read_config_word(pdev, PCI_CLASS_DEVICE, &value);
        if (rv < 0)
                dev_err(dev, "Mythic%d: Unable to read PCI class code\n",
                                mythic_dev->idr);
          dev_info(dev, "Mythic%d: Class code: 0x%x",
                        mythic_dev->idr, value);
           rv = pci_read_config_word(pdev, 0xD10, &value);
        if (rv < 0)
                dev_err(dev, "Mythic%d: Unable to read PCI class code\n",
                                mythic_dev->idr);
        dev_info(dev, "Mythic%d: Slot ID: 0x%x", mythic_dev->idr, value);

        dev_info(dev, "Mythic%d: Driver (v%s) loaded successfully\n",
                        mythic_dev->idr, MYTHIC_DRIVER_VERSION);

        return 0;


out_pci_disable:
        pci_disable_device(pdev);

        dev_info(dev, "Mythic%d: Driver loading unsuccessful\n",
                        mythic_dev->idr);
out_pci_request_regions:
        pci_release_regions(pdev);

        return rv;
}

static void mythic_ipu_remove(struct pci_dev *pdev)
{
        struct mythic_ipu *mythic_dev = pci_get_drvdata(pdev);


      	unmap_bars(pdev, mythic_dev);
        pci_release_regions(pdev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
        pci_cleanup_aer_uncorrect_error_status(pdev);
#endif

        /* AER disable */
        pci_disable_pcie_error_reporting(pdev);

        pci_disable_device(pdev);
       /* mythic_node_remove(mythic_dev); */
        idr_remove(&mythic_idr, mythic_dev->idr);
        dev_info(&pdev->dev, "Mythic%d: Driver unloaded\n",
                        mythic_dev->idr);
}


static const struct pci_device_id mythic_pci_id_tbl[] = {
        { PCI_DEVICE(MYTHIC_VENDOR_ID, PCI_ANY_ID) },
        {}
};
MODULE_DEVICE_TABLE(pci, mythic_pci_id_tbl);

static struct pci_driver mythic_pci_card = {
        .name           = DRV_MODULE_NAME,
        .id_table       = mythic_pci_id_tbl,
        .probe          = mythic_ipu_probe,
        .remove         = mythic_ipu_remove,
};
static void mythic_exit(void)
{
        pci_unregister_driver(&mythic_pci_card);
        class_destroy(ipu_dma_class);

}

static int __init mythic_init(void)
{
        int rv = -EIO;

        /*dbg_dev_l0("Mythic debug log level : %d", MYTHIC_DEBUG_LEVEL);*/
	printk("Inside pci driver init \n");
        ipu_dma_class = class_create(THIS_MODULE, "mythic_dma");
        if (IS_ERR(ipu_dma_class))
                return PTR_ERR(ipu_dma_class);
       /*mythic_dma_class->devnode = dev_nod_perm;*/

        rv = pci_register_driver(&mythic_pci_card);
        if(rv < 0)
		printk("error in registering\n");
	return rv;
}

module_init(mythic_init);
module_exit(mythic_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abhijith S <abhijith.s@ignitarium.com>");
MODULE_DESCRIPTION("PCIE driver for Mythic IPU");
