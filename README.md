# CoKey Host Driver

This repository contains the CoKey Linux host driver to support CoKey USB
devices. For further details regarding CoKey see the corresponding paper
publication on ACSAC 2016:

    J. Horsch, S. Wessel and C. Eckert. CoKey: Fast Token-Based Cooperative
    Cryptography. In Proceedings of the 32th Annual Computer Security
    Applications Conference, ACSAC ’16. ACM, 2016.

Note that this is a **Proof of Concept (PoC)** implementation and should **not**
be used in a productive environment.

## Target

The module was tested on Debian with a 4.2 Linux Kernel, any other distribution or Kernel version is untested.

## Known Problems

The module does *not* build for kernels using the new `skcipher` Linux crypto
API. For more limitations/long-term TODOs see source.

## Installation

Note that you need a CoKey token, e.g., a USB armory with the CoKey USB gadget
driver running, for using the host driver and the associated crypto
algorithms.

 1. Install packages to allow kernel module building, e.g., `apt-get install
    linux-headers-amd64`
 2. Build the kernel module using the provided Makefile
 3. Load the module: `insmod cokey.ko`

## Example Test Case: Block Device Encryption

### Setup encrypted disk image and initial mount

 1. Create test image file:

        dd if=/dev/zero of=test.img bs=1MiB count=10

 2. Setup loop device

        sudo losetup --find --show ~/test.img

 3. Setup LUKS and dm-crypt

        sudo cryptsetup -y luksFormat -c aesusb-ctr-plain:sha256 -s 128 /dev/loop0
        sudo cryptsetup luksOpen /dev/loop0 cokey-dev

 4. Generate file system (you can choose a different one)

        sudo mkfs.ext3 -j /dev/mapper/cokey-dev
 
 5. Mount FS for the first time

        sudo mount /dev/mapper/cokey-dev mnt/
        
### Subsequent Mount

To mount an already created image:

        sudo losetup --find --show ~/test.img
        sudo cryptsetup luksOpen /dev/loop0 cokey-dev
        sudo mount /dev/mapper/cokey-dev mnt/

### Subsequent Unmount

To unmount a mounted image:

        sudo umount mnt/
        sudo cryptsetup luksClose cokey-dev
        sudo losetup -d /dev/loop0 

## Optimize Performance when using USB Armory as CoKey device
If you use a USBArmory as CoKey USB device, make sure it uses the fastest AES
drivers available, e.g. Sahara for AES with 128 bit keys or aes-asm for other
versions.

Additionally, you can make sure that the CPU runs with maximum performance:

        echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

## License

The CoKey host driver Linux kernel module is licensed under GPLv2.
 
Copyright (c) 2015-2016, Fraunhofer AISEC.
Author: Julian Horsch <julian.horsch@aisec.fraunhofer.de>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
