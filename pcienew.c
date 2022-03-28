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
#include "mythic.h"

#if KERNEL_VERSION(4, 9, 0) > LINUX_VERSION_CODE
#include <linux/interrupt.h>
#endif

#define MYTHIC_DRIVER_VERSION           "1.0.0"

#define dev_to_mythic_dev(_dev)         pci_get_drvdata(to_pci_dev(_dev))
#define BAR_MASK_NIBBLE                 0x0000000F

static DEFINE_MUTEX(core_lock);
static DEFINE_IDR(mythic_idr);

struct class *mythic_dma_class;

//static ssize_t mythic_dev_read(char *buf,size_t len, uint32_t *off);
//static ssize_t mythic_dev_write(char *buf, size_t len, uint32_t *off);


int mythic_dev_read(char *buf,size_t len, uint32_t offset)
{

        struct mythic_dma *dma;
        struct mythic_ipu *mythic_dev;
        char *reg;
        //uint32_t offset = *off;
	printk("offset is 0x%x\n", offset);
        dma->bar = dma->dma_bar[BAR_0];
        reg = dma->bar + offset;
        memcpy(buf, reg, len);


        return 0;
}

EXPORT_SYMBOL(mythic_dev_read);

int mythic_dev_write(char *buf, size_t len, uint32_t offset)
{
        struct mythic_dma *dma;
        struct mythic_ipu *mythic_dev;
        char *reg;
        //uint32_t offset = *off;

        dma->bar = dma->dma_bar[BAR_0];
        reg = dma->bar + offset;
        memcpy(reg, buf, len);


        return 0;
}

EXPORT_SYMBOL(mythic_dev_write);

static int mythic_ipu_probe(struct pci_dev *pdev,
                const struct pci_device_id *pdev_id)
{
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
        mythic_dev->dma.device_class = mythic_dma_class;

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

        return rv;
}

static void mythic_ipu_remove(struct pci_dev *pdev)
{
        struct mythic_ipu *mythic_dev = pci_get_drvdata(pdev);


        /*unmap_bars(pdev, mythic_dev);*/
        pci_release_regions(pdev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
        pci_cleanup_aer_uncorrect_error_status(pdev);
#endif

        /* AER disable */
        pci_disable_pcie_error_reporting(pdev);

        pci_disable_device(pdev);
       /*mythic_node_remove(mythic_dev);*/
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
        class_destroy(mythic_dma_class);

}

static int __init mythic_init(void)
{
        int rv = -EIO;

        dbg_dev_l0("Mythic debug log level : %d", MYTHIC_DEBUG_LEVEL);

        mythic_dma_class = class_create(THIS_MODULE, "mythic_dma");
        if (IS_ERR(mythic_dma_class))
                return PTR_ERR(mythic_dma_class);
       /*mythic_dma_class->devnode = dev_nod_perm;*/

        rv = pci_register_driver(&mythic_pci_card);
        return rv;
}

module_init(mythic_init);
module_exit(mythic_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abhijith S <abhijith.s@ignitarium.com>");
MODULE_DESCRIPTION("PCIE driver for Mythic IPU");
