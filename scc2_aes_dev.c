/*
 * Copyright (c) WithSecure Corporation
 *
 * https://github.com/usbarmory/mxc-scc2
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation under version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/dma-mapping.h>
#include <net/sock.h>
#include <asm/io.h>

#include "mxc_scc2_driver.h"

#define DEVICE_NAME "scc2_aes"
#define AES_BLOCK_SIZE 16

static dev_t dev;
static struct cdev c_dev;
static struct class *cl;

static uint32_t *iv;
static char aes_buf_in[SZ_4K];
static char aes_buf_out[SZ_4K];

enum scc2_cmd {
	SET_MODE,
	SET_IV,
};

enum scc2_mode {
	ENCRYPT_CBC,
	DECRYPT_CBC,
};

static struct scc2_cfg {
	uint8_t mode;
	char    iv[AES_BLOCK_SIZE];
} cfg;

static void clear_iv(void)
{
	/*
	 * After the first block ciphering the SCCv2 internally updates the IV
	 * in CBC mode.
	 */
	if (iv != NULL) {
		kfree(iv);
		iv = NULL;
	}

	return;
}

static void aes_encrypt(uint16_t length, char *data, scc_cypher_mode_t mode,
			char *out)
{
	int part_no;
	uint32_t part_phys;
	void *part_base;
	void *black_ram;
	dma_addr_t handle;

	scc_return_t ret;

	black_ram = dma_alloc_coherent(NULL, length, &handle, GFP_KERNEL);
	if (black_ram == NULL) {
		printk(KERN_ERR "scc2_aes: failed to allocate black ram\n");
		return;
	}

	ret = scc_allocate_partition(0, &part_no, &part_base, &part_phys);
	if (ret != SCC_RET_OK) {
		printk(KERN_ERR "scc2_aes: failed to allocate partition, error %x\n", ret);
		goto out;
	}

	ret = scc_engage_partition(part_base, NULL, SCM_PERM_TH_READ | SCM_PERM_TH_WRITE | SCM_PERM_HD_READ | SCM_PERM_HD_WRITE);
	if (ret != SCC_RET_OK) {
		printk(KERN_ERR "scc2_aes: failed to engage partition, error %x\n", ret);
		goto out;
	}

	memcpy(part_base, data, length);

	ret = scc_encrypt_region((uint32_t) part_base, 0, length, (uint8_t *) virt_to_phys(black_ram), iv, mode);
	if (ret != SCC_RET_OK) {
		printk(KERN_ERR "scc2_aes: failed to encrypt block, error %x\n", ret);
		goto out;
	}

	memcpy(out, black_ram, length);

	ret = scc_release_partition(part_base);
	if (ret != SCC_RET_OK) {
		printk(KERN_ERR "scc2_aes: failed to release partition, error %x\n", ret);
		goto out;
	}

out:
	dma_free_coherent(NULL, length, black_ram, handle);
	return;
}

static void aes_decrypt(uint16_t length, char *data, scc_cypher_mode_t mode,
			char *out)
{
	int part_no;
	uint32_t part_phys;
	void *part_base;
	void *black_ram;
	dma_addr_t handle;

	scc_return_t ret;

	black_ram = dma_alloc_coherent(NULL, length, &handle, GFP_KERNEL);
	if (black_ram == NULL) {
		printk(KERN_ALERT "scc2_aes: failed to allocate black ram\n");
		return;
	}

	ret = scc_allocate_partition(0, &part_no, &part_base, &part_phys);
	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes: failed to allocate partition, error %x\n", ret);
		goto out;
	}

	ret = scc_engage_partition(part_base, NULL, SCM_PERM_TH_READ | SCM_PERM_TH_WRITE | SCM_PERM_HD_READ | SCM_PERM_HD_WRITE);
	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes: failed to engage partition, error %x\n", ret);
		goto out;
	}

	memcpy(black_ram, data, length);

	ret = scc_decrypt_region((uint32_t) part_base, 0, length, (uint8_t *) virt_to_phys(black_ram), iv, mode);
	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes: failed to decrypt black ram, error %x\n", ret);
		goto out;
	}

	memcpy(out, part_base, length);

	ret = scc_release_partition(part_base);
	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes: failed to release partition, error %x\n", ret);
		goto out;
	}

out:
	dma_free_coherent(NULL, length, black_ram, handle);
	return;
}

static ssize_t device_read(struct file *filp, char __user *buff,
			   size_t len, loff_t *off)
{
	int errlen;

	if (len > SZ_4K) {
		len = SZ_4K;
	}

	errlen = copy_to_user(buff, aes_buf_out, len);

	return len - errlen;
}

static ssize_t device_write(struct file *filp, const char __user *buff,
			    size_t len, loff_t *off)
{
	int errlen;

	if (len > SZ_4K) {
		len = SZ_4K;
	}

	errlen = copy_from_user(aes_buf_in, buff, len);

	switch (cfg.mode) {
	case ENCRYPT_CBC:
		aes_encrypt(len, aes_buf_in, SCC_CYPHER_MODE_CBC, aes_buf_out);
		clear_iv();
		break;
	case DECRYPT_CBC:
		aes_decrypt(len, aes_buf_in, SCC_CYPHER_MODE_CBC, aes_buf_out);
		clear_iv();
		break;
	default:
		printk(KERN_ALERT "scc2_aes: invalid configuration mode (%d)\n", cfg.mode);
		break;
	}

	return len - errlen;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int rlen;

	switch (cmd) {
	case SET_MODE:
		if (arg == ENCRYPT_CBC) {
			printk(KERN_DEBUG "scc2_aes: setting CBC encryption mode\n");
			cfg.mode = ENCRYPT_CBC;
		} else if (arg == DECRYPT_CBC) {
			printk(KERN_DEBUG "scc2_aes: setting CBC decryption mode\n");
			cfg.mode = DECRYPT_CBC;
		} else {
			printk(KERN_ALERT "scc2_aes: invalid configuration mode (%lu)\n", arg);
		}
		break;
	case SET_IV:
		printk(KERN_DEBUG "scc2_aes: setting initialization vector\n");

		if (iv == NULL) {
			iv = kzalloc(AES_BLOCK_SIZE, GFP_KERNEL);
		}

		rlen = copy_from_user(iv, (char *) arg, AES_BLOCK_SIZE);

		break;
	}

	return 0;
}

static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.unlocked_ioctl = device_ioctl,
};

int register_chardev(void)
{
	int major;

	major = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);

	if (major < 0) {
		printk(KERN_ERR "scc2_aes: could not allocate character device\n");
		goto errout;
	}

	cl = class_create(THIS_MODULE, "crypto");
	if (cl == NULL) {
		printk(KERN_ERR "scc2_aes: class creation failed\n");
		unregister_chrdev_region(dev, 1);
		goto errout;
	}

	if (device_create(cl, NULL, dev, NULL, DEVICE_NAME) == NULL) {
		printk(KERN_ERR "scc2_aes: device creation failed\n");
		class_destroy(cl);
		unregister_chrdev_region(dev, 1);
		goto errout;
	}

	cdev_init(&c_dev, &fops);

	if (cdev_add(&c_dev, dev, 1) == -1) {
		printk(KERN_ERR "scc2_aes: device addition failed\n");
		device_destroy(cl, dev);
		class_destroy(cl);
		unregister_chrdev_region(dev, 1);
		goto errout;
	}

	printk(KERN_INFO "scc2_aes: registered /dev/%s\n", DEVICE_NAME);

	return 0;

errout:
	return -1;
}

void unregister_chardev(void)
{
	cdev_del(&c_dev);
	device_destroy(cl, dev);
	class_destroy(cl);
	unregister_chrdev_region(dev, 1);

	printk(KERN_INFO "scc2_aes: unregistered /dev/%s\n", DEVICE_NAME);
}

static int scc2_aes_dev_init(void)
{
	scc_config_t *scc_config = NULL;
	uint32_t status;

	scc_config = scc_get_configuration();
	if (scc_config == NULL) {
		printk(KERN_ERR "scc2_aes: cannot get SCC configuration, aborting\n");
		goto errout;
	}

	if (scc_config->scm_version == 0) {
		printk(KERN_ERR "scc2_aes: cannot read scm_version, aborting\n");
		goto errout;
	}

	cfg.mode = ENCRYPT_CBC;

	iv = kzalloc(AES_BLOCK_SIZE, GFP_KERNEL);
	if (iv == NULL) {
		printk(KERN_ERR "scc2_aes: unable to allocate IV, aborting\n");
		goto errout;
	}

	if (register_chardev() != 0) {
		printk(KERN_ERR "scc2_aes: character device registration failed\n");
		goto errout;
	}

	scc_read_register(SCM_STATUS_REG, &status);

	if (status & SCM_STATUS_MSS_SEC) {
		printk(KERN_INFO "scc2_aes: Secure State detected\n");
	} else {
		printk(KERN_NOTICE "scc2_aes: WARNING - not in Secure State, NIST test key in effect\n");
	}

	return 0;

errout:
	return -1;
}

static void scc2_aes_dev_exit(void)
{
	printk(KERN_INFO "scc2_aes: shutting down\n");

	unregister_chardev();

	clear_iv();
}

module_init(scc2_aes_dev_init);
module_exit(scc2_aes_dev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Inverse Path");
MODULE_DESCRIPTION("NXP Security Controller (SCCv2) character device interface");
