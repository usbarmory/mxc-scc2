NXP Security Controller (SCCv2) - Linux driver
==============================================

The SCCv2 is a built-in hardware module that implements secure RAM and a
dedicated AES cryptographic engine for encryption/decryption operations.

A device specific random 256-bit SCC key is fused in each SoC at manufacturing
time, this key is unreadable and can only be used with the SCCv2 for AES
encryption/decryption of user data.

This directory contains a Linux kernel driver for the SCCv2 and an additional
interfacing module, which allocates character device /dev/scc2_aes for
userspace encryption and decryption operations.

The kernel driver is a port of the original Freescale one for Linux 3.x with
assorted bugfixes and the addition of a new separate character device driver.

Authors
=======

Andrea Barisani <andrea@inversepath.com>  
Andrej Rosano   <andrej@inversepath.com>  

Based on a driver from Freescale Semiconductor, Inc., additional thanks to
Julian Horsch <julian.horsch@aisec.fraunhofer.de> for its contribution to the
port.

Compiling
=========

The following instructions assume compilation on a native armv7 architecture,
when cross compiling adjust ARCH and CROSS_COMPILE variables accordingly.

```
# the Makefile attempts to locate your Linux kernel source tree, if this fails
# it can be passed with a Makefile variable (e.g. `make KERNEL_SRC=path`)
git clone https://github.com/inversepath/mxc-scc2
cd mxc-scc2
make
make modules_install
```

Once installed the two resulting modules can be loaded in the traditional
manner:

```
modprobe scc2     # SCCv2 driver
modprobe scc2_aes # character device driver for userspace access
```

The probing of the SCCv2 module depends on its the Device Tree (dts) inclusion
in running Linux kernel. The following example is taken from the USB armory
[dtsi](https://github.com/inversepath/usbarmory/blob/master/software/kernel_conf/imx53-usbarmory-common.dtsi)
which includes the SCCv2 device for its i.MX53 SoC:

```
	soc {
		aips@60000000 {
			scc2: scc2@63fb4000 {
				compatible = "fsl,imx53-scc2";
				reg = <0x63fb4000 0x4000>,
				      <0x07000000 0x4000>;
				interrupts = <21 23>;
			};
		};
	};
```

Character device interface
==========================

The following IOCTLs are defined for character device /dev/scc2_aes:

```
ioctl(file, SET_MODE, ENCRYPT_CBC)
  Sets AES-256 encryption with Cipher Block Chaining (CBC)

ioctl(file, SET_MODE, DECRYPT_CBC)
  Sets AES-256 decryption with Cipher Block Chaining (CBC)

ioctl(file, SET_IV, (char *) iv)
  Sets the Initialization Vector (IV), this is required only once before
  encryption/decryption. After the first block ciphersing the SCCv2
  internally updates the IV in CBC mode.
```

Once the mode and IV are set, plaintext/ciphertext can be sent to the SCCv2 for
encryption/decryption by issuing a write() operation of 16-bytes blocks on
/dev/scc2_aes, up to 256 blocks (4096 bytes) can be sent at once.

Each write() operation must be followed by a read() operation of the same size
to read back the results, misaligned and mismatched write()/read() operations
will cause errors.

Example (psuedocode):
```
fd = open("/dev/scc2_aes", O_RDWR)

ioctl(fd, SET_IV, iv)

ioctl(fd, SET_MODE, ENCRYPT_CBC)
write(fd, plaintext, 4096)
read(fd, ciphertext, 4096)

ioctl(fd, SET_MODE, DECRYPT_CBC)
write(fd, ciphertext, 4096)
read(fd, plaintext, 4096)
```

A userspace example usage, with OpenSSL test comparison, is provided in the
[scc2_test](https://github.com/inversepath/mxc-scc2/blob/master/scc2_test)
Ruby script.

**IMPORTANT**: the SCCv2 internal key is available only when Secure Boot (HAB)
is enabled, otherwise the AES-256 NIST standard test key is set. For this
reason the OpenSSL and SCCv2 output comparison of the scc2_test script matches
only on units that do not have HAB enabled. The secure operation of the SCCv2,
in production deployments, should always be paired with Secure Boot activation.

The scc2_aes module, when not in Secure State, issues the following warning at
load time:

```
scc2_aes: WARNING - not in Secure State, NIST test key in effect
```

When Secure State is correctly detected the module issues following message at
load time:

```
scc2_aes: Secure State detected
```

The following reference output illustrates a reference test run on a
[USB armory](https://inversepath.com/usbarmory) without Secure Boot enabled.

```
NIST test AES-256 key:        603deb1015ca71be2b73aef0857d7781
                              1f352c073b6108d72d9810a30914dff4
initialization vector:        000102030405060708090a0b0c0d0e0f
plaintext:                    6bc1bee22e409f96e93d7e117393172a

ciphertext round 1 (OpenSSL): f58c4c04d6e5f1ba779eabfb5f7bfbd6
ciphertext round 1 (SCCv2):   f58c4c04d6e5f1ba779eabfb5f7bfbd6
ciphertext round 2 (OpenSSL): eb2d9e942831bd84dff00db9776b8088
ciphertext round 2 (SCCv2):   eb2d9e942831bd84dff00db9776b8088
        match!

 plaintext round 1 (OpenSSL): 6bc1bee22e409f96e93d7e117393172a
 plaintext round 1 (SCCv2):   6bc1bee22e409f96e93d7e117393172a
 plaintext round 2 (OpenSSL): 6bc1bee22e409f96e93d7e117393172a
 plaintext round 2 (SCCv2):   6bc1bee22e409f96e93d7e117393172a
        match!

```

License
=======

NXP Security Controller (SCCv2) driver | https://github.com/inversepath/mxc-scc2

Copyright (c) 2016 Inverse Path S.r.l.  
Copyright (c) 2004-2011 Freescale Semiconductor, Inc. All Rights Reserved.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation under version 3 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

See accompanying LICENSE file for full details.
