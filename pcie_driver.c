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


static DEFINE_MUTEX(core_lock);
static DEFINE_IDR(mythic_idr);

extern int mdma_init(void *dev);

/*enum pci_bar_no {
        BAR_0,
        BAR_1,
        BAR_2,
        BAR_3,
        BAR_4,
        BAR_5,
};

struct ipu_dma {
        int major;
        int minor;
        dev_t devno;
        struct cdev cdev;
        int channels;           // Total dma channels
        struct class *device_class;
        void *dma_handle;       // Points to the PCI device
        void __iomem *bar;
        void __iomem *dma_bar[4];
};

struct pcie_ipu {
        unsigned int idr;
        struct pci_dev *pdev;
        void __iomem *bar[6];
        struct cdev cdev;
        dev_t devno;
        char devname[15];
        struct ipu_dma dma;
};*/


struct class *ipu_dma_class;

int test_check(void)
{
	printk("INSIDE PCI DRIVER\n");
	return 0;
}
EXPORT_SYMBOL(test_check);
int mythic_dev_read(char *buf,size_t len, uint32_t offset)
{

        struct mythic_dma *dma;
        /*struct pcie_ipu *mythic_dev;
	dma = (struct mythic_dma *)filp->private_data;
        mythic_dev = container_of(dma, struct mythic_ipu, dma);*/
	//struct pcie_ipu *mythic_dev = dev_to_mythic_dev(dev);
        char *reg;
	printk("offset value is %x\n",offset);
        dma->bar = dma->dma_bar[BAR_0];
	reg = dma->bar + offset;
	printk("reg value is %s\n",reg);
//        memcpy(buf, reg, len);


        return 0;
}
EXPORT_SYMBOL(mythic_dev_read);

int mythic_dev_write(char *buf, size_t len, uint32_t offset)
{
        struct mythic_dma *dma;
        /*struct pcie_ipu *mythic_dev;
        dma = (struct mythic_dma *)filp->private_data;
        mythic_dev = container_of(dma, struct mythic_ipu, dma);*/

	char *reg;

        dma->bar = dma->dma_bar[BAR_0];
        reg = dma->bar + offset;
        memcpy(reg, buf, len);


        return 0;
}
EXPORT_SYMBOL(mythic_dev_write);

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
        struct mythic_ipu *mythic_dev;
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
            dev_err(dev, "Mythic%d: Unable to create mythic DMA"
                                " device ioctls\n",
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
