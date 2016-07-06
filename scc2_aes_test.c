/*
 * Copyright (c) 2016 Inverse Path S.r.l.
 *
 * https://github.com/inversepath/mxc-scc2
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

static int aes_encrypt_test(void)
{
	int part_no, length;
	uint32_t part_phys;
	uint32_t plaintext[4];
	uint32_t iv[4];
	void *part_base;
	void *black_ram;
	dma_addr_t handle;

	scc_return_t ret;

	iv[0] = 0x03020100;
	iv[1] = 0x07060504;
	iv[2] = 0x0b0a0908;
	iv[3] = 0x0f0e0d0c;

	plaintext[0] = 0xe2bec16b;
	plaintext[1] = 0x969f402e;
	plaintext[2] = 0x117e3de9;
	plaintext[3] = 0x2a179373;
	length = sizeof(plaintext);

	// key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
	// iv:          000102030405060708090a0b0c0d0e0f
	// test vector: 6bc1bee22e409f96e93d7e117393172a # 1st block
	// cipher text: f58c4c04d6e5f1ba779eabfb5f7bfbd6
	// test vector: 6bc1bee22e409f96e93d7e117393172a # 2nd block
	// cipher text: eb2d9e942831bd84dff00db9776b8088

	printk(KERN_ALERT "scc2_aes_test: ---- encryption test ----\n");

	black_ram = dma_alloc_coherent(NULL, length, &handle, GFP_KERNEL);

	if (!black_ram) {
		printk(KERN_ALERT "scc2_aes_test: failed to allocate black ram\n");
		return 0;
	}

	ret = scc_allocate_partition(0, &part_no, &part_base, &part_phys);

	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes_test: failed to allocate partition, error %x\n", ret);
		goto out;
	}
	printk(KERN_DEBUG "scc2_aes_test: allocated part_no: %x, part_base: %p, part_phys: %x\n",
	       part_no, part_base, part_phys);

	ret = scc_engage_partition(part_base, NULL, SCM_PERM_TH_READ | SCM_PERM_TH_WRITE | SCM_PERM_HD_READ | SCM_PERM_HD_WRITE);

	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes_test: failed to engage partition, error %x\n", ret);
		goto out;
	}
	printk(KERN_DEBUG "scc2_aes_test: engaged part_no: %x\n", part_no);

	writel(plaintext[0], (void *)(part_base + 0));
	writel(plaintext[1], (void *)(part_base + 4));
	writel(plaintext[2], (void *)(part_base + 8));
	writel(plaintext[3], (void *)(part_base + 12));

	print_hex_dump(KERN_DEBUG, "scc2_aes_test: partition ", DUMP_PREFIX_ADDRESS,
	               length, 1, part_base, length, false);

	print_hex_dump(KERN_DEBUG, "scc2_aes_test: black pre ", DUMP_PREFIX_ADDRESS,
	               length, 1, black_ram, length, false);

	// 1st block

	ret = scc_encrypt_region((uint32_t) part_base, 0, length, (uint8_t *) virt_to_phys(black_ram), iv, SCC_CYPHER_MODE_CBC);

	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes_test: failed to encrypt region, error %x\n", ret);
		goto out;
	}
	printk(KERN_DEBUG "scc2_aes_test: encrypted region part_base: %p\n", part_base);

	print_hex_dump(KERN_DEBUG, "scc2_aes_test: black post ", DUMP_PREFIX_ADDRESS,
	               length, 1, black_ram, length, false);

	// 2nd block

	ret = scc_encrypt_region((uint32_t) part_base, 0, length, (uint8_t *) virt_to_phys(black_ram), NULL, SCC_CYPHER_MODE_CBC);

	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes_test: failed to encrypt region, error %x\n", ret);
		goto out;
	}
	printk(KERN_DEBUG "scc2_aes_test: encrypted region part_base: %p\n", part_base);

	print_hex_dump(KERN_DEBUG, "scc2_aes_test: black post ", DUMP_PREFIX_ADDRESS,
	               length, 1, black_ram, length, false);

	// done

	ret = scc_release_partition(part_base);

	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes_test: failed to release partition, error %x\n", ret);
		goto out;
	}
	printk(KERN_DEBUG "scc2_aes_test: released part_no: %x\n", part_no);

out:
	dma_free_coherent(NULL, length, black_ram, handle);
	return 0;
}

static int aes_decrypt_test(void)
{
	int part_no, length;
	uint32_t part_phys;
	uint32_t ciphertext[4];
	uint32_t iv[4];
	void *part_base;
	void *black_ram;
	dma_addr_t handle;

	scc_return_t ret;

	iv[0] = 0x03020100;
	iv[1] = 0x07060504;
	iv[2] = 0x0b0a0908;
	iv[3] = 0x0f0e0d0c;

	ciphertext[0] = 0x044c8cf5;
	ciphertext[1] = 0xbaf1e5d6;
	ciphertext[2] = 0xfbab9e77;
	ciphertext[3] = 0xd6fb7b5f;
	length = sizeof(ciphertext);

	// key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
	// iv:          000102030405060708090a0b0c0d0e0f
	// test vector: f58c4c04d6e5f1ba779eabfb5f7bfbd6 # 1st block
	// plaintext:   6bc1bee22e409f96e93d7e117393172a
	// test vector: eb2d9e942831bd84dff00db9776b8088 # 2nd block
	// plaintext:   6bc1bee22e409f96e93d7e117393172a

	printk(KERN_ALERT "scc2_aes_test: ---- decryption test ----\n");

	black_ram = dma_alloc_coherent(NULL, length, &handle, GFP_KERNEL);

	if (!black_ram) {
		printk(KERN_ALERT "scc2_aes_test: failed to allocate black ram\n");
		return 0;
	}

	ret = scc_allocate_partition(0, &part_no, &part_base, &part_phys);

	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes_test: failed to allocate partition, error %x\n", ret);
		goto out;
	}
	printk(KERN_DEBUG "scc2_aes_test: allocated part_no: %x, part_base: %p, part_phys: %x\n",
	       part_no, part_base, part_phys);

	ret = scc_engage_partition(part_base, NULL, SCM_PERM_TH_READ | SCM_PERM_TH_WRITE | SCM_PERM_HD_READ | SCM_PERM_HD_WRITE);

	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes_test: failed to engage partition, error %x\n", ret);
		goto out;
	}
	printk(KERN_DEBUG "scc2_aes_test: engaged part_no: %x\n", part_no);

	memcpy(black_ram, ciphertext, length);

	print_hex_dump(KERN_DEBUG, "scc2_aes_test: black          ", DUMP_PREFIX_ADDRESS,
	               length, 1, black_ram, length, false);

	print_hex_dump(KERN_DEBUG, "scc2_aes_test: partition pre  ", DUMP_PREFIX_ADDRESS,
	               length, 1, part_base, length, false);

	// 1st block

	ret = scc_decrypt_region((uint32_t) part_base, 0, length, (uint8_t *) virt_to_phys(black_ram), iv, SCC_CYPHER_MODE_CBC);

	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes_test: failed to decrypt black ram, error %x\n", ret);
		goto out;
	}
	printk(KERN_DEBUG "scc2_aes_test: decrypted black ram to region part_base: %p\n", part_base);

	print_hex_dump(KERN_DEBUG, "scc2_aes_test: partition post ", DUMP_PREFIX_ADDRESS,
	               length, 1, part_base, length, false);

	// 2nd block

	ciphertext[0] = 0x949e2deb;
	ciphertext[1] = 0x84bd3128;
	ciphertext[2] = 0xb90df0df;
	ciphertext[3] = 0x88806b77;

	memcpy(black_ram, ciphertext, length);

	ret = scc_decrypt_region((uint32_t) part_base, 0, length, (uint8_t *) virt_to_phys(black_ram), NULL, SCC_CYPHER_MODE_CBC);

	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes_test: failed to decrypt black ram, error %x\n", ret);
		goto out;
	}
	printk(KERN_DEBUG "scc2_aes_test: decrypted black ram to region part_base: %p\n", part_base);

	print_hex_dump(KERN_DEBUG, "scc2_aes_test: partition post ", DUMP_PREFIX_ADDRESS,
	               length, 1, part_base, length, false);

	// done

	ret = scc_release_partition(part_base);

	if (ret != SCC_RET_OK) {
		printk(KERN_ALERT "scc2_aes_test: failed to release partition, error %x\n", ret);
		goto out;
	}
	printk(KERN_DEBUG "scc2_aes_test: released part_no: %x\n", part_no);

out:
	dma_free_coherent(NULL, length, black_ram, handle);
	return 0;
}
