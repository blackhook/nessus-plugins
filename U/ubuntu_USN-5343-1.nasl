#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5343-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159160);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2016-2853",
    "CVE-2016-2854",
    "CVE-2018-5995",
    "CVE-2019-19449",
    "CVE-2020-12655",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
    "CVE-2020-26139",
    "CVE-2020-26147",
    "CVE-2020-26555",
    "CVE-2020-26558",
    "CVE-2020-36322",
    "CVE-2020-36385",
    "CVE-2021-0129",
    "CVE-2021-3483",
    "CVE-2021-3506",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-3612",
    "CVE-2021-3679",
    "CVE-2021-20292",
    "CVE-2021-20317",
    "CVE-2021-23134",
    "CVE-2021-28688",
    "CVE-2021-28972",
    "CVE-2021-29650",
    "CVE-2021-32399",
    "CVE-2021-33033",
    "CVE-2021-33034",
    "CVE-2021-33098",
    "CVE-2021-34693",
    "CVE-2021-38160",
    "CVE-2021-38198",
    "CVE-2021-38204",
    "CVE-2021-38208",
    "CVE-2021-39648",
    "CVE-2021-40490",
    "CVE-2021-42008",
    "CVE-2021-43389",
    "CVE-2021-45095",
    "CVE-2021-45469",
    "CVE-2021-45485",
    "CVE-2022-0492"
  );
  script_xref(name:"USN", value:"5343-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Linux kernel vulnerabilities (USN-5343-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5343-1 advisory.

  - The aufs module for the Linux kernel 3.x and 4.x does not properly restrict the mount namespace, which
    allows local users to gain privileges by mounting an aufs filesystem on top of a FUSE filesystem, and then
    executing a crafted setuid program. (CVE-2016-2853)

  - The aufs module for the Linux kernel 3.x and 4.x does not properly maintain POSIX ACL xattr data, which
    allows local users to gain privileges by leveraging a group-writable setgid directory. (CVE-2016-2854)

  - The pcpu_embed_first_chunk function in mm/percpu.c in the Linux kernel through 4.14.14 allows local users
    to obtain sensitive address information by reading dmesg data from a pages/cpu printk call.
    (CVE-2018-5995)

  - In the Linux kernel 5.0.21, mounting a crafted f2fs filesystem image can lead to slab-out-of-bounds read
    access in f2fs_build_segment_manager in fs/f2fs/segment.c, related to init_min_max_mtime in
    fs/f2fs/segment.c (because the second argument to get_seg_entry is not validated). (CVE-2019-19449)

  - An issue was discovered in xfs_agf_verify in fs/xfs/libxfs/xfs_alloc.c in the Linux kernel through 5.6.10.
    Attackers may trigger a sync of excessive duration via an XFS v5 image with crafted metadata, aka
    CID-d0c7feaf8767. (CVE-2020-12655)

  - A vulnerability was found in Linux Kernel where refcount leak in llcp_sock_bind() causing use-after-free
    which might lead to privilege escalations. (CVE-2020-25670)

  - A vulnerability was found in Linux Kernel, where a refcount leak in llcp_sock_connect() causing use-after-
    free which might lead to privilege escalations. (CVE-2020-25671)

  - A memory leak vulnerability was found in Linux kernel in llcp_sock_connect (CVE-2020-25672)

  - A vulnerability was found in Linux kernel where non-blocking socket in llcp_sock_connect() leads to leak
    and eventually hanging-up the system. (CVE-2020-25673)

  - An issue was discovered in the kernel in NetBSD 7.1. An Access Point (AP) forwards EAPOL frames to other
    clients even though the sender has not yet successfully authenticated to the AP. This might be abused in
    projected Wi-Fi networks to launch denial-of-service attacks against connected clients and makes it easier
    to exploit other vulnerabilities in connected clients. (CVE-2020-26139)

  - An issue was discovered in the Linux kernel 5.8.9. The WEP, WPA, WPA2, and WPA3 implementations reassemble
    fragments even though some of them were sent in plaintext. This vulnerability can be abused to inject
    packets and/or exfiltrate selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP data-confidentiality protocol is used. (CVE-2020-26147)

  - Bluetooth legacy BR/EDR PIN code pairing in Bluetooth Core Specification 1.0B through 5.2 may permit an
    unauthenticated nearby device to spoof the BD_ADDR of the peer device to complete pairing without
    knowledge of the PIN. (CVE-2020-26555)

  - Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby
    man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication
    procedure) by reflection of the public key and the authentication evidence of the initiating device,
    potentially permitting this attacker to complete authenticated pairing with the responding device using
    the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit
    at a time. (CVE-2020-26558)

  - An issue was discovered in the FUSE filesystem implementation in the Linux kernel before 5.10.6, aka
    CID-5d069dbe8aaf. fuse_do_getattr() calls make_bad_inode() in inappropriate situations, causing a system
    crash. NOTE: the original fix for this vulnerability was incomplete, and its incompleteness is tracked as
    CVE-2021-28950. (CVE-2020-36322)

  - An issue was discovered in the Linux kernel before 5.10. drivers/infiniband/core/ucma.c has a use-after-
    free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is
    called, aka CID-f5449e74802c. (CVE-2020-36385)

  - Improper access control in BlueZ may allow an authenticated user to potentially enable information
    disclosure via adjacent access. (CVE-2021-0129)

  - A flaw was found in the Nosy driver in the Linux kernel. This issue allows a device to be inserted twice
    into a doubly-linked list, leading to a use-after-free when one of these devices is removed. The highest
    threat from this vulnerability is to confidentiality, integrity, as well as system availability. Versions
    before kernel 5.12-rc6 are affected (CVE-2021-3483)

  - An out-of-bounds (OOB) memory access flaw was found in fs/f2fs/node.c in the f2fs module in the Linux
    kernel in versions before 5.12.0-rc4. A bounds check failure allows a local attacker to gain access to
    out-of-bounds memory leading to a system crash or a leak of internal kernel information. The highest
    threat from this vulnerability is to system availability. (CVE-2021-3506)

  - A flaw double-free memory corruption in the Linux kernel HCI device initialization subsystem was found in
    the way user attach malicious HCI TTY Bluetooth device. A local user could use this flaw to crash the
    system. This flaw affects all the Linux kernel versions starting from 3.13. (CVE-2021-3564)

  - A use-after-free in function hci_sock_bound_ioctl() of the Linux kernel HCI subsystem was found in the way
    user calls ioct HCIUNBLOCKADDR or other way triggers race condition of the call hci_unregister_dev()
    together with one of the calls hci_sock_blacklist_add(), hci_sock_blacklist_del(), hci_get_conn_info(),
    hci_get_auth_info(). A privileged local user could use this flaw to crash the system or escalate their
    privileges on the system. This flaw affects the Linux kernel versions prior to 5.13-rc5. (CVE-2021-3573)

  - An out-of-bounds memory write flaw was found in the Linux kernel's joystick devices subsystem in versions
    before 5.9-rc1, in the way the user calls ioctl JSIOCSBTNMAP. This flaw allows a local user to crash the
    system or possibly escalate their privileges on the system. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system availability. (CVE-2021-3612)

  - A lack of CPU resource in the Linux kernel tracing module functionality in versions prior to 5.14-rc3 was
    found in the way user uses trace ring buffer in a specific way. Only privileged local users (with
    CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service.
    (CVE-2021-3679)

  - There is a flaw reported in the Linux kernel in versions before 5.9 in
    drivers/gpu/drm/nouveau/nouveau_sgdma.c in nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The issue
    results from the lack of validating the existence of an object prior to performing operations on the
    object. An attacker with a local account with a root privilege, can leverage this vulnerability to
    escalate privileges and execute code in the context of the kernel. (CVE-2021-20292)

  - A flaw was found in the Linux kernel. A corrupted timer tree caused the task wakeup to be missing in the
    timerqueue_add function in lib/timerqueue.c. This flaw allows a local attacker with special user
    privileges to cause a denial of service, slowing and eventually stopping the system while running OSP.
    (CVE-2021-20317)

  - Use After Free vulnerability in nfc sockets in the Linux Kernel before 5.12.4 allows local attackers to
    elevate their privileges. In typical configurations, the issue can only be triggered by a privileged local
    user with the CAP_NET_RAW capability. (CVE-2021-23134)

  - The fix for XSA-365 includes initialization of pointers such that subsequent cleanup code wouldn't use
    uninitialized or stale values. This initialization went too far and may under certain conditions also
    overwrite pointers which are in need of cleaning up. The lack of cleanup would result in leaking
    persistent grants. The leak in turn would prevent fully cleaning up after a respective guest has died,
    leaving around zombie domains. All Linux versions having the fix for XSA-365 applied are vulnerable.
    XSA-365 was classified to affect versions back to at least 3.11. (CVE-2021-28688)

  - In drivers/pci/hotplug/rpadlpar_sysfs.c in the Linux kernel through 5.11.8, the RPA PCI Hotplug driver has
    a user-tolerable buffer overflow when writing a new device name to the driver from userspace, allowing
    userspace to write data to the kernel stack frame directly. This occurs because add_slot_store and
    remove_slot_store mishandle drc_name '\0' termination, aka CID-cc7a0bb058b8. (CVE-2021-28972)

  - An issue was discovered in the Linux kernel before 5.11.11. The netfilter subsystem allows attackers to
    cause a denial of service (panic) because net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h
    lack a full memory barrier upon the assignment of a new table value, aka CID-175e476b8cdf.
    (CVE-2021-29650)

  - net/bluetooth/hci_request.c in the Linux kernel through 5.12.2 has a race condition for removal of the HCI
    controller. (CVE-2021-32399)

  - The Linux kernel before 5.11.14 has a use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c because
    the CIPSO and CALIPSO refcounting for the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads
    to writing an arbitrary value. (CVE-2021-33033)

  - In the Linux kernel before 5.12.4, net/bluetooth/hci_event.c has a use-after-free when destroying an
    hci_chan, aka CID-5c4c8c954409. This leads to writing an arbitrary value. (CVE-2021-33034)

  - Improper input validation in the Intel(R) Ethernet ixgbe driver for Linux before version 3.17.3 may allow
    an authenticated user to potentially enable denial of service via local access. (CVE-2021-33098)

  - net/can/bcm.c in the Linux kernel through 5.12.10 allows local users to obtain sensitive information from
    kernel stack memory because parts of a data structure are uninitialized. (CVE-2021-34693)

  - ** DISPUTED ** In drivers/char/virtio_console.c in the Linux kernel before 5.13.4, data corruption or loss
    can be triggered by an untrusted device that supplies a buf->len value exceeding the buffer size. NOTE:
    the vendor indicates that the cited data corruption is not a vulnerability in any existing use case; the
    length validation was added solely for robustness in the face of anomalous host OS behavior.
    (CVE-2021-38160)

  - arch/x86/kvm/mmu/paging_tmpl.h in the Linux kernel before 5.12.11 incorrectly computes the access
    permissions of a shadow page, leading to a missing guest protection page fault. (CVE-2021-38198)

  - drivers/usb/host/max3421-hcd.c in the Linux kernel before 5.13.6 allows physically proximate attackers to
    cause a denial of service (use-after-free and panic) by removing a MAX-3421 USB device in certain
    situations. (CVE-2021-38204)

  - net/nfc/llcp_sock.c in the Linux kernel before 5.12.10 allows local unprivileged users to cause a denial
    of service (NULL pointer dereference and BUG) by making a getsockname call after a certain type of failure
    of a bind call. (CVE-2021-38208)

  - In gadget_dev_desc_UDC_show of configfs.c, there is a possible disclosure of kernel heap memory due to a
    race condition. This could lead to local information disclosure with System execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-160822094References: Upstream kernel (CVE-2021-39648)

  - A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in
    the Linux kernel through 5.13.13. (CVE-2021-40490)

  - The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab
    out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.
    (CVE-2021-42008)

  - An issue was discovered in the Linux kernel before 5.14.15. There is an array-index-out-of-bounds flaw in
    the detach_capi_ctr function in drivers/isdn/capi/kcapi.c. (CVE-2021-43389)

  - pep_sock_accept in net/phonet/pep.c in the Linux kernel through 5.15.8 has a refcount leak.
    (CVE-2021-45095)

  - In __f2fs_setxattr in fs/f2fs/xattr.c in the Linux kernel through 5.15.11, there is an out-of-bounds
    memory access when an inode has an invalid last xattr entry. (CVE-2021-45469)

  - In the IPv6 implementation in the Linux kernel before 5.13.3, net/ipv6/output_core.c has an information
    leak because of certain use of a hash table which, although big, doesn't properly consider that IPv6-based
    attackers can typically choose among many IPv6 source addresses. (CVE-2021-45485)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5343-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.4.0-1102");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.4.0-1138");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.4.0-1102");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.4.0-1138");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.4.0-1102");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.4.0-1138");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1102-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1103-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1138-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-222-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-222-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1102-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1103-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1138-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-222");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-222-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-222-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1102-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1103-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1138-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-222");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-222-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-222-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1102-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1103-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1138-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-222-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-222-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-222-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-222-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-cloud-tools-4.4.0-1103");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-4.4.0-1103");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-4.4.0-1103");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lts-xenial-cloud-tools-4.4.0-222");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lts-xenial-tools-4.4.0-222");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1102-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1103-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1138-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-222-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-222-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-1138-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-222-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1102-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1103-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1138-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-222");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-222-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-222-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-xenial");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(14\.04|16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2016-2853', 'CVE-2016-2854', 'CVE-2018-5995', 'CVE-2019-19449', 'CVE-2020-12655', 'CVE-2020-25670', 'CVE-2020-25671', 'CVE-2020-25672', 'CVE-2020-25673', 'CVE-2020-26139', 'CVE-2020-26147', 'CVE-2020-26555', 'CVE-2020-26558', 'CVE-2020-36322', 'CVE-2020-36385', 'CVE-2021-0129', 'CVE-2021-3483', 'CVE-2021-3506', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3612', 'CVE-2021-3679', 'CVE-2021-20292', 'CVE-2021-20317', 'CVE-2021-23134', 'CVE-2021-28688', 'CVE-2021-28972', 'CVE-2021-29650', 'CVE-2021-32399', 'CVE-2021-33033', 'CVE-2021-33034', 'CVE-2021-33098', 'CVE-2021-34693', 'CVE-2021-38160', 'CVE-2021-38198', 'CVE-2021-38204', 'CVE-2021-38208', 'CVE-2021-39648', 'CVE-2021-40490', 'CVE-2021-42008', 'CVE-2021-43389', 'CVE-2021-45095', 'CVE-2021-45469', 'CVE-2021-45485', 'CVE-2022-0492');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5343-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '14.04', 'pkgname': 'linux-aws', 'pkgver': '4.4.0.1102.100'},
    {'osver': '14.04', 'pkgname': 'linux-aws-cloud-tools-4.4.0-1102', 'pkgver': '4.4.0-1102.107'},
    {'osver': '14.04', 'pkgname': 'linux-aws-headers-4.4.0-1102', 'pkgver': '4.4.0-1102.107'},
    {'osver': '14.04', 'pkgname': 'linux-aws-tools-4.4.0-1102', 'pkgver': '4.4.0-1102.107'},
    {'osver': '14.04', 'pkgname': 'linux-buildinfo-4.4.0-1102-aws', 'pkgver': '4.4.0-1102.107'},
    {'osver': '14.04', 'pkgname': 'linux-buildinfo-4.4.0-222-generic', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-buildinfo-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-cloud-tools-4.4.0-1102-aws', 'pkgver': '4.4.0-1102.107'},
    {'osver': '14.04', 'pkgname': 'linux-cloud-tools-4.4.0-222-generic', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-cloud-tools-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-cloud-tools-generic-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-cloud-tools-virtual-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-generic-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-headers-4.4.0-1102-aws', 'pkgver': '4.4.0-1102.107'},
    {'osver': '14.04', 'pkgname': 'linux-headers-4.4.0-222', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-headers-4.4.0-222-generic', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-headers-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-headers-aws', 'pkgver': '4.4.0.1102.100'},
    {'osver': '14.04', 'pkgname': 'linux-headers-generic-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-headers-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-headers-virtual-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-image-4.4.0-1102-aws', 'pkgver': '4.4.0-1102.107'},
    {'osver': '14.04', 'pkgname': 'linux-image-4.4.0-222-generic', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-image-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-image-aws', 'pkgver': '4.4.0.1102.100'},
    {'osver': '14.04', 'pkgname': 'linux-image-extra-virtual-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-image-generic-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-image-unsigned-4.4.0-222-generic', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-image-unsigned-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-image-virtual-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-lts-xenial-cloud-tools-4.4.0-222', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-lts-xenial-tools-4.4.0-222', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-modules-4.4.0-1102-aws', 'pkgver': '4.4.0-1102.107'},
    {'osver': '14.04', 'pkgname': 'linux-modules-4.4.0-222-generic', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-modules-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-modules-extra-4.4.0-222-generic', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-signed-generic-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-signed-image-generic-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-signed-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-signed-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-tools-4.4.0-1102-aws', 'pkgver': '4.4.0-1102.107'},
    {'osver': '14.04', 'pkgname': 'linux-tools-4.4.0-222-generic', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-tools-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-tools-aws', 'pkgver': '4.4.0.1102.100'},
    {'osver': '14.04', 'pkgname': 'linux-tools-generic-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-tools-virtual-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '14.04', 'pkgname': 'linux-virtual-lts-xenial', 'pkgver': '4.4.0.222.193'},
    {'osver': '16.04', 'pkgname': 'linux-aws', 'pkgver': '4.4.0.1138.143'},
    {'osver': '16.04', 'pkgname': 'linux-aws-cloud-tools-4.4.0-1138', 'pkgver': '4.4.0-1138.152'},
    {'osver': '16.04', 'pkgname': 'linux-aws-headers-4.4.0-1138', 'pkgver': '4.4.0-1138.152'},
    {'osver': '16.04', 'pkgname': 'linux-aws-tools-4.4.0-1138', 'pkgver': '4.4.0-1138.152'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-1103-kvm', 'pkgver': '4.4.0-1103.112'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-1138-aws', 'pkgver': '4.4.0-1138.152'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-222-generic', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-1103-kvm', 'pkgver': '4.4.0-1103.112'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-1138-aws', 'pkgver': '4.4.0-1138.152'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-222', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-222-generic', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-generic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-1103-kvm', 'pkgver': '4.4.0-1103.112'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-1138-aws', 'pkgver': '4.4.0-1138.152'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-222', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-222-generic', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-headers-aws', 'pkgver': '4.4.0.1138.143'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '4.4.0.1103.101'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-generic-trusty', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-virtual-trusty', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1103-kvm', 'pkgver': '4.4.0-1103.112'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1138-aws', 'pkgver': '4.4.0-1138.152'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-222-generic', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws', 'pkgver': '4.4.0.1138.143'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-generic-trusty', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-virtual-trusty', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.4.0.1103.101'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-222-generic', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-kvm', 'pkgver': '4.4.0.1103.101'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-cloud-tools-4.4.0-1103', 'pkgver': '4.4.0-1103.112'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-headers-4.4.0-1103', 'pkgver': '4.4.0-1103.112'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-tools-4.4.0-1103', 'pkgver': '4.4.0-1103.112'},
    {'osver': '16.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-1103-kvm', 'pkgver': '4.4.0-1103.112'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-1138-aws', 'pkgver': '4.4.0-1138.152'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-222-generic', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-1138-aws', 'pkgver': '4.4.0-1138.152'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-222-generic', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '4.4.0.1138.143'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-source', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.4.0', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-1103-kvm', 'pkgver': '4.4.0-1103.112'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-1138-aws', 'pkgver': '4.4.0-1138.152'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-222', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-222-generic', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-222-lowlatency', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-tools-aws', 'pkgver': '4.4.0.1138.143'},
    {'osver': '16.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.4.0-222.255'},
    {'osver': '16.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '4.4.0.1103.101'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-xenial', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-virtual', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-utopic', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-vivid', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-wily', 'pkgver': '4.4.0.222.229'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-xenial', 'pkgver': '4.4.0.222.229'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-cloud-tools-4.4.0-1102 / etc');
}
