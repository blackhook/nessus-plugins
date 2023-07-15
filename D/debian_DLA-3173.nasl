#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3173. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(166822);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/03");

  script_cve_id(
    "CVE-2021-4037",
    "CVE-2022-0171",
    "CVE-2022-1184",
    "CVE-2022-1679",
    "CVE-2022-2153",
    "CVE-2022-2602",
    "CVE-2022-2663",
    "CVE-2022-2905",
    "CVE-2022-3028",
    "CVE-2022-3061",
    "CVE-2022-3176",
    "CVE-2022-3303",
    "CVE-2022-3586",
    "CVE-2022-3621",
    "CVE-2022-3625",
    "CVE-2022-3629",
    "CVE-2022-3633",
    "CVE-2022-3635",
    "CVE-2022-3646",
    "CVE-2022-3649",
    "CVE-2022-3919",
    "CVE-2022-4167",
    "CVE-2022-4272",
    "CVE-2022-20421",
    "CVE-2022-20422",
    "CVE-2022-39188",
    "CVE-2022-39190",
    "CVE-2022-39842",
    "CVE-2022-40307",
    "CVE-2022-41222",
    "CVE-2022-41674",
    "CVE-2022-42719",
    "CVE-2022-42720",
    "CVE-2022-42721",
    "CVE-2022-42722",
    "CVE-2022-43750"
  );

  script_name(english:"Debian DLA-3173-1 : linux-5.10 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3173 advisory.

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

  - A use-after-free flaw was found in the Linux kernel's Atheros wireless adapter driver in the way a user
    forces the ath9k_htc_wait_for_target function to fail with some input messages. This flaw allows a local
    user to crash or potentially escalate their privileges on the system. (CVE-2022-1679)

  - In binder_inc_ref_for_node of binder.c, there is a possible way to corrupt memory due to a use after free.
    This could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-239630375References: Upstream kernel (CVE-2022-20421)

  - In emulation_proc_handler of armv8_deprecated.c, there is a possible way to corrupt memory due to a race
    condition. This could lead to local escalation of privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid
    ID: A-237540956References: Upstream kernel (CVE-2022-20422)

  - A flaw was found in the Linux kernel's KVM when attempting to set a SynIC IRQ. This issue makes it
    possible for a misbehaving VMM to write to SYNIC/STIMER MSRs, causing a NULL pointer dereference. This
    flaw allows an unprivileged local attacker on the host to issue specific ioctl calls, causing a kernel
    oops condition that results in a denial of service. (CVE-2022-2153)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - An out-of-bounds memory read flaw was found in the Linux kernel's BPF subsystem in how a user calls the
    bpf_tail_call function with a key larger than the max_entries of the map. This flaw allows a local user to
    gain unauthorized access to data. (CVE-2022-2905)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

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

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_bmap_lookup_at_level of the file fs/nilfs2/inode.c of the component nilfs2. The manipulation leads
    to null pointer dereference. It is possible to launch the attack remotely. It is recommended to apply a
    patch to fix this issue. The identifier of this vulnerability is VDB-211920. (CVE-2022-3621)

  - A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function
    devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    VDB-211929 was assigned to this vulnerability. (CVE-2022-3625)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects
    the function vsock_connect of the file net/vmw_vsock/af_vsock.c of the component IPsec. The manipulation
    leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211930 is the identifier
    assigned to this vulnerability. (CVE-2022-3629)

  - A vulnerability classified as problematic has been found in Linux Kernel. Affected is the function
    j1939_session_destroy of the file net/can/j1939/transport.c of the component IPsec. The manipulation leads
    to memory leak. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability
    is VDB-211932. (CVE-2022-3633)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function tst_timer of the file drivers/atm/idt77252.c of the component IPsec. The manipulation
    leads to use after free. It is recommended to apply a patch to fix this issue. VDB-211934 is the
    identifier assigned to this vulnerability. (CVE-2022-3635)

  - A vulnerability, which was classified as problematic, has been found in Linux Kernel. This issue affects
    the function nilfs_attach_log_writer of the file fs/nilfs2/segment.c of the component BPF. The
    manipulation leads to memory leak. The attack may be initiated remotely. It is recommended to apply a
    patch to fix this issue. The identifier VDB-211961 was assigned to this vulnerability. (CVE-2022-3646)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_new_inode of the file fs/nilfs2/inode.c of the component BPF. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211992. (CVE-2022-3649)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

  - An issue was discovered in net/netfilter/nf_tables_api.c in the Linux kernel before 5.19.6. A denial of
    service can occur upon binding to an already bound chain. (CVE-2022-39190)

  - An issue was discovered in the Linux kernel before 5.19. In pxa3xx_gcu_write in
    drivers/video/fbdev/pxa3xx-gcu.c, the count parameter has a type conflict of size_t versus int, causing an
    integer overflow and bypassing the size check. After that, because it is used as the third argument to
    copy_from_user(), a heap overflow may occur. (CVE-2022-39842)

  - An issue was discovered in the Linux kernel through 5.19.8. drivers/firmware/efi/capsule-loader.c has a
    race condition with a resultant use-after-free. (CVE-2022-40307)

  - mm/mremap.c in the Linux kernel before 5.13.3 has a use-after-free via a stale TLB because an rmap lock is
    not held during a PUD move. (CVE-2022-41222)

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

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1017425");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux-5.10");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3173");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4037");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0171");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1679");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-20421");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-20422");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2153");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2905");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3028");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3061");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3176");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3303");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3625");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3629");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3633");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3635");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3646");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3649");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39188");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3919");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39190");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39842");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40307");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41222");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4167");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41674");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42719");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4272");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42720");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42721");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43750");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux-5.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-5.10 packages.

For Debian 10 buster, these problems have been fixed in version 5.10.149-2~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1679");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3649");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.19");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp-lpae', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-rt-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-686', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-686-pae', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-amd64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-arm64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-armmp-lpae', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-cloud-amd64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-cloud-arm64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-common', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-common-rt', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-686-pae', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-amd64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-arm64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-686', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-686-pae', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-amd64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-arm64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-armmp-lpae', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-cloud-amd64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-cloud-arm64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-common', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-common-rt', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-686-pae', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-amd64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-arm64', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-pae-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-signed-template', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-signed-template', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-amd64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-arm64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-i386-signed-template', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-686-pae-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-amd64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-arm64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-pae-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-pae-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-amd64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-amd64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-arm64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-arm64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-lpae', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-amd64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-arm64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-armmp-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-pae-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-pae-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-amd64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-amd64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-arm64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-arm64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-lpae', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-amd64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-arm64-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-armmp', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-armmp-dbg', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.17', 'reference': '5.10.149-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.19', 'reference': '5.10.149-2~deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-config-5.10 / linux-doc-5.10 / linux-headers-5.10-armmp / etc');
}
