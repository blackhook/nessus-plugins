#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5257. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(166232);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/01");

  script_cve_id(
    "CVE-2021-4037",
    "CVE-2022-0171",
    "CVE-2022-1184",
    "CVE-2022-2602",
    "CVE-2022-2663",
    "CVE-2022-3061",
    "CVE-2022-3176",
    "CVE-2022-3303",
    "CVE-2022-20421",
    "CVE-2022-39188",
    "CVE-2022-39842",
    "CVE-2022-40307",
    "CVE-2022-41674",
    "CVE-2022-42719",
    "CVE-2022-42720",
    "CVE-2022-42721",
    "CVE-2022-42722"
  );

  script_name(english:"Debian DSA-5257-1 : linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5257 advisory.

  - A vulnerability was found in the fs/inode.c:inode_init_owner() function logic of the LInux kernel that
    allows local users to create files for the XFS file-system with an unintended group ownership and with
    group execution and SGID permission bits set, in a scenario where a directory is SGID and belongs to a
    certain group and is writable by a user who is not a member of this group. This can lead to excessive
    permissions granted in case when they should not. This vulnerability is similar to the previous
    CVE-2018-13405 and adds the missed fix for the XFS. (CVE-2021-4037)

  - A flaw was found in the Linux kernel. The existing KVM SEV API has a vulnerability that allows a non-root
    (host) user-level application to crash the host kernel by creating a confidential guest VM instance in AMD
    CPU that supports Secure Encrypted Virtualization (SEV). (CVE-2022-0171)

  - A use-after-free flaw was found in fs/ext4/namei.c:dx_insert_block() in the Linux kernel's filesystem sub-
    component. This flaw allows a local attacker with a user privilege to cause a denial of service.
    (CVE-2022-1184)

  - In binder_inc_ref_for_node of binder.c, there is a possible way to corrupt memory due to a use after free.
    This could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-239630375References: Upstream kernel (CVE-2022-20421)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - Found Linux Kernel flaw in the i740 driver. The Userspace program could pass any values to the driver
    through ioctl() interface. The driver doesn't check the value of 'pixclock', so it may cause a divide by
    zero error. (CVE-2022-3061)

  - There exists a use-after-free in io_uring in the Linux kernel. Signalfd_poll() and binder_poll() use a
    waitqueue whose lifetime is the current task. It will send a POLLFREE notification to all waiters before
    the queue is freed. Unfortunately, the io_uring poll doesn't handle POLLFREE. This allows a use-after-free
    to occur if a signalfd or binder fd is polled with io_uring poll, and the waitqueue gets freed. We
    recommend upgrading past commit fc78b2fc21f10c4c9c4d5d659a685710ffa63659 (CVE-2022-3176)

  - A race condition flaw was found in the Linux kernel sound subsystem due to improper locking. It could lead
    to a NULL pointer dereference while handling the SNDCTL_DSP_SYNC ioctl. A privileged local user (root or
    member of the audio group) could use this flaw to crash the system, resulting in a denial of service
    condition (CVE-2022-3303)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

  - An issue was discovered in the Linux kernel before 5.19. In pxa3xx_gcu_write in
    drivers/video/fbdev/pxa3xx-gcu.c, the count parameter has a type conflict of size_t versus int, causing an
    integer overflow and bypassing the size check. After that, because it is used as the third argument to
    copy_from_user(), a heap overflow may occur. (CVE-2022-39842)

  - An issue was discovered in the Linux kernel through 5.19.8. drivers/firmware/efi/capsule-loader.c has a
    race condition with a resultant use-after-free. (CVE-2022-40307)

  - An issue was discovered in the Linux kernel before 5.19.16. Attackers able to inject WLAN frames could
    cause a buffer overflow in the ieee80211_bss_info_update function in net/mac80211/scan.c. (CVE-2022-41674)

  - A use-after-free in the mac80211 stack when parsing a multi-BSSID element in the Linux kernel 5.2 through
    5.19.x before 5.19.16 could be used by attackers (able to inject WLAN frames) to crash the kernel and
    potentially execute code. (CVE-2022-42719)

  - Various refcounting bugs in the multi-BSS handling in the mac80211 stack in the Linux kernel 5.1 through
    5.19.x before 5.19.16 could be used by local attackers (able to inject WLAN frames) to trigger use-after-
    free conditions to potentially execute code. (CVE-2022-42720)

  - A list management bug in BSS handling in the mac80211 stack in the Linux kernel 5.1 through 5.19.x before
    5.19.16 could be used by local attackers (able to inject WLAN frames) to corrupt a linked list and, in
    turn, potentially execute code. (CVE-2022-42721)

  - In the Linux kernel 5.8 through 5.19.x before 5.19.16, local attackers able to inject WLAN frames into the
    mac80211 stack could cause a NULL pointer dereference denial-of-service attack against the beacon
    protection of P2P devices. (CVE-2022-42722)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5257");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4037");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0171");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-20421");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3061");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3176");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3303");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39188");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39842");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40307");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41674");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42719");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42720");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42721");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42722");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.149-1.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42719");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-16-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-16-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loop-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakup-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-armmp-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-16-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-18-s390x-di");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'bpftool', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'hyperv-daemons', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'libcpupower-dev', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'libcpupower1', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-arm', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-s390', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-x86', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-cpupower', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-doc', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-4kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-4kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-5kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-686', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-686-pae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-amd64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-arm64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-armmp-lpae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-cloud-amd64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-cloud-arm64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-common', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-common-rt', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-loongson-3', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-marvell', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-octeon', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-powerpc64le', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-rpi', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-rt-686-pae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-rt-amd64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-rt-arm64', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-rt-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-16-s390x', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp-lpae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-loongson-3', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-marvell', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-octeon', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-powerpc64le', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rpi', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rt-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-headers-s390x', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-4kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-4kc-malta-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-5kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-5kc-malta-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-686-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-686-pae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-686-pae-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-686-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-amd64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-arm64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-armmp-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-armmp-lpae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-armmp-lpae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-cloud-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-cloud-amd64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-cloud-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-cloud-arm64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-loongson-3', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-loongson-3-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-marvell', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-marvell-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-octeon', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-octeon-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-powerpc64le', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-powerpc64le-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rpi', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rpi-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-686-pae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-686-pae-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-amd64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-arm64-unsigned', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-rt-armmp-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-s390x', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-16-s390x-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-pae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-686-pae-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-amd64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-arm64-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x-dbg', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-libc-dev', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-perf', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-source', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'linux-support-5.10.0-16', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-armmp-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-marvell-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'usbip', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-16-s390x-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-4kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-5kc-malta-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-loongson-3-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-octeon-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-powerpc64le-di', 'reference': '5.10.149-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-18-s390x-di', 'reference': '5.10.149-1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'affs-modules-5.10.0-16-4kc-malta-di / etc');
}
