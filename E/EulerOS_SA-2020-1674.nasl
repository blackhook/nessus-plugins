#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137516);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2014-3180",
    "CVE-2014-4508",
    "CVE-2014-4608",
    "CVE-2014-5206",
    "CVE-2014-5207",
    "CVE-2014-7970",
    "CVE-2016-3951",
    "CVE-2016-9756",
    "CVE-2017-12153",
    "CVE-2017-13080",
    "CVE-2017-13693",
    "CVE-2017-8068",
    "CVE-2018-1000204",
    "CVE-2018-13093",
    "CVE-2018-9383",
    "CVE-2018-9389",
    "CVE-2019-10220",
    "CVE-2019-14895",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-14898",
    "CVE-2019-14901",
    "CVE-2019-16230",
    "CVE-2019-18675",
    "CVE-2019-19054",
    "CVE-2019-19056",
    "CVE-2019-19057",
    "CVE-2019-19060",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19066",
    "CVE-2019-19073",
    "CVE-2019-19074",
    "CVE-2019-19227",
    "CVE-2019-19319",
    "CVE-2019-19332",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19527",
    "CVE-2019-19528",
    "CVE-2019-19530",
    "CVE-2019-19531",
    "CVE-2019-19532",
    "CVE-2019-19533",
    "CVE-2019-19534",
    "CVE-2019-19536",
    "CVE-2019-19537",
    "CVE-2019-19768",
    "CVE-2019-19922",
    "CVE-2019-19965",
    "CVE-2019-19966",
    "CVE-2019-20054",
    "CVE-2019-20096",
    "CVE-2019-20636",
    "CVE-2019-2215",
    "CVE-2019-5108",
    "CVE-2019-9458",
    "CVE-2020-10720",
    "CVE-2020-10942",
    "CVE-2020-11494",
    "CVE-2020-11565",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-11668",
    "CVE-2020-12464",
    "CVE-2020-12652",
    "CVE-2020-12653",
    "CVE-2020-12654",
    "CVE-2020-12655",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-13143",
    "CVE-2020-2732",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-8992",
    "CVE-2020-9383"
  );
  script_bugtraq_id(
    68126,
    68214,
    69214,
    69216,
    70319
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2020-1674)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):In the Linux kernel before
    5.5.8, get_raw_socket in drivers/vhost/ net.c lacks
    validation of an sk_family field, which might allow
    attackers to trigger kernel stack corruption via
    crafted system calls.(CVE-2020-10942)In the Linux
    kernel 5.0.21, a setxattr operation, after a mount of a
    crafted ext4 image, can cause a slab-out-of-bounds
    write access because of an ext4_xattr_set_entry
    use-after-free in fs/ext4/xattr.c when a large old_size
    value is used in a memset call.(CVE-2019-19319)In
    kernel/compat.c in the Linux kernel before 3.17, as
    used in Google Chrome OS and other products, there is a
    possible out-of-bounds read. restart_syscall uses
    uninitialized data when restarting
    compat_sys_nanosleep. NOTE: this is disputed because
    the code path is unreachable.(CVE-2014-3180)In the
    Linux kernel 5.4.0-rc2, there is a use-after-free
    (read) in the __blk_add_trace function in
    kernel/trace/blktrace.c (which is used to fill out a
    blk_io_trace structure and place it in a per-cpu
    sub-buffer).(CVE-2019-19768)There is a use-after-free
    vulnerability in the Linux kernel through 5.5.2 in the
    vc_do_resize function in
    drivers/tty/vt/vt.c.(CVE-2020-8647)There is a
    use-after-free vulnerability in the Linux kernel
    through 5.5.2 in the vgacon_invert_region function in
    drivers/video/console/vgacon.c.(CVE-2020-8649)drivers/g
    pu/drm/radeon/radeon_display.c in the Linux kernel
    5.2.14 does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference. NOTE: A
    third-party software maintainer states that the work
    queue allocation is happening during device
    initialization, which for a graphics card occurs during
    boot. It is not attacker controllable and OOM at that
    time is highly unlikely.(CVE-2019-16230)There is a
    use-after-free vulnerability in the Linux kernel
    through 5.5.2 in the n_tty_receive_buf_common function
    in drivers/tty/ n_tty.c.(CVE-2020-8648)A flaw was
    discovered in the way that the KVM hypervisor handled
    instruction emulation for an L2 guest when nested
    virtualisation is enabled. Under some circumstances, an
    L2 guest may trick the L0 guest into accessing
    sensitive L1 resources that should be inaccessible to
    the L2 guest.(CVE-2020-2732)An issue was discovered in
    the Linux kernel through 5.5.6. set_fdc in
    drivers/block/floppy.c leads to a wait_til_ready
    out-of-bounds read because the FDC index is not checked
    for errors before assigning it, aka
    CID-2e90ca68b0d2.(CVE-2020-9383)ext4_protect_reserved_i
    node in fs/ext4/block_validity.c in the Linux kernel
    through 5.5.3 allows attackers to cause a denial of
    service (soft lockup) via a crafted journal
    size.(CVE-2020-8992)Wi-Fi Protected Access (WPA and
    WPA2) allows reinstallation of the Group Temporal Key
    (GTK) during the group key handshake, allowing an
    attacker within radio range to replay frames from
    access points to clients.(CVE-2017-13080)Linux Kernel
    version 3.18 to 4.16 incorrectly handles an SG_IO ioctl
    on /dev/sg0 with dxfer_direction=SG_DXFER_FROM_DEV and
    an empty 6-byte cmdp. This may lead to copying up to
    1000 kernel heap pages to the userspace. This has been
    fixed upstream in
    https://github.com/torvalds/linux/commit/a45b599ad808c3
    c982fdcdc12b0b8611c2f92824 already. The problem has
    limited scope, as users don't usually have permissions
    to access SCSI devices. On the other hand, e.g. the
    Nero user manual suggests doing `chmod o+r+w /dev/sg*`
    to make the devices accessible. NOTE: third parties
    dispute the relevance of this report, noting that the
    requirement for an attacker to have both the
    CAP_SYS_ADMIN and CAP_SYS_RAWIO capabilities makes it
    'virtually impossible to exploit.'(CVE-2018-1000204)The
    Linux kernel through 5.3.13 has a start_offset+size
    Integer Overflow in cpia2_remap_buffer in
    drivers/media/usb/cpia2/cpia2_core.c because cpia2 has
    its own mmap implementation. This allows local users
    (with /dev/video0 access) to obtain read and write
    permissions on kernel physical pages, which can
    possibly result in a privilege
    escalation.(CVE-2019-18675)arch/x86/kvm/emulate.c in
    the Linux kernel before 4.8.12 does not properly
    initialize Code Segment (CS) in certain error cases,
    which allows local users to obtain sensitive
    information from kernel stack memory via a crafted
    application.(CVE-2016-9756)Double free vulnerability in
    drivers/ net/usb/cdc_ncm.c in the Linux kernel before
    4.5 allows physically proximate attackers to cause a
    denial of service (system crash) or possibly have
    unspecified other impact by inserting a USB device with
    an invalid USB descriptor.(CVE-2016-3951)Linux Kernel
    contains an out-of-bounds read flaw in the
    asn1_ber_decoder() function in lib/asn1_decoder.c that
    is triggered when decoding ASN.1 data. This may allow a
    remote attacker to disclose potentially sensitive
    memory contents.(CVE-2018-9383)Linux Kernel contains a
    flaw in the ip6_setup_cork() function in
    net/ipv6/ip6_output.c that is triggered when handling
    too small IPv6 MTU sizes. This may allow a local
    attacker to cause a crash or potentially gain elevated
    privileges.(CVE-2018-9389)In the Android kernel in the
    video driver there is a use after free due to a race
    condition. This could lead to local escalation of
    privilege with no additional execution privileges
    needed. User interaction is not needed for
    exploitation.(CVE-2019-9458)An out-of-bounds memory
    write issue was found in the Linux Kernel, version 3.13
    through 5.4, in the way the Linux kernel's KVM
    hypervisor handled the 'KVM_GET_EMULATED_CPUID'
    ioctl(2) request to get CPUID features emulated by the
    KVM hypervisor. A user or process able to access the
    '/dev/kvm' device could use this flaw to crash the
    system, resulting in a denial of
    service.(CVE-2019-19332)kernel/sched/fair.c in the
    Linux kernel before 5.3.9, when cpu.cfs_quota_us is
    used (e.g., with Kubernetes), allows attackers to cause
    a denial of service against non-cpu-bound applications
    by generating a workload that triggers unwanted slice
    expiration, aka CID-de53fd7aedb1. (In other words,
    although this slice expiration would typically be seen
    with benign workloads, it is possible that an attacker
    could calculate how many stray requests are required to
    force an entire Kubernetes cluster into a
    low-performance state caused by slice expiration, and
    ensure that a DDoS attack sent that number of stray
    requests. An attack does not affect the stability of
    the kernel it only causes mismanagement of application
    execution.)(CVE-2019-19922)An exploitable
    denial-of-service vulnerability exists in the Linux
    kernel prior to mainline 5.3. An attacker could exploit
    this vulnerability by triggering AP to send IAPP
    location updates for stations before the required
    authentication process has completed. This could lead
    to different denial-of-service scenarios, either by
    causing CAM table attacks, or by leading to traffic
    flapping if faking already existing clients in other
    nearby APs of the same wireless infrastructure. An
    attacker can forge Authentication and Association
    Request packets to trigger this
    vulnerability.(CVE-2019-5108)A heap-based buffer
    overflow vulnerability was found in the Linux kernel,
    version kernel-2.6.32, in Marvell WiFi chip driver. A
    remote attacker could cause a denial of service (system
    crash) or, possibly execute arbitrary code, when the
    lbs_ibss_join_existing function is called after a STA
    connects to an AP.(CVE-2019-14896)A stack-based buffer
    overflow was found in the Linux kernel, version
    kernel-2.6.32, in Marvell WiFi chip driver. An attacker
    is able to cause a denial of service (system crash) or,
    possibly execute arbitrary code, when a STA works in
    IBSS mode (allows connecting stations together without
    the use of an AP) and connects to another
    STA.(CVE-2019-14897)In the Linux kernel through 5.4.6,
    there is a NULL pointer dereference in
    drivers/scsi/libsas/sas_discover.c because of
    mishandling of port disconnection during discovery,
    related to a PHY down race condition, aka
    CID-f70267f379b5.(CVE-2019-19965)In the Linux kernel
    before 5.1.6, there is a use-after-free in cpia2_exit()
    in drivers/media/usb/cpia2/cpia2_v4l.c that will cause
    denial of service, aka
    CID-dea37a972655.(CVE-2019-19966)In the Linux kernel
    before 5.1, there is a memory leak in
    __feat_register_sp() in net/dccp/feat.c, which may
    cause denial of service, aka
    CID-1d3ff0950e2b.(CVE-2019-20096)In the Linux kernel
    before 5.0.6, there is a NULL pointer dereference in
    drop_sysctl_table() in fs/proc/proc_sysctl.c, related
    to put_links, aka
    CID-23da9588037e.(CVE-2019-20054)drivers/
    net/usb/pegasus.c in the Linux kernel 4.9.x before
    4.9.11 interacts incorrectly with the CONFIG_VMAP_STACK
    option, which allows local users to cause a denial of
    service (system crash or memory corruption) or possibly
    have unspecified other impact by leveraging use of more
    than one virtual page for a DMA
    scatterlist.(CVE-2017-8068)A heap-based buffer overflow
    was discovered in the Linux kernel, all versions 3.x.x
    and 4.x.x before 4.18.0, in Marvell WiFi chip driver.
    The flaw could occur when the station attempts a
    connection negotiation during the handling of the
    remote devices country settings. This could allow the
    remote device to cause a denial of service (system
    crash) or possibly execute arbitrary
    code.(CVE-2019-14895)The acpi_ds_create_operands()
    function in drivers/acpi/acpica/dsutils.c in the Linux
    kernel through 4.12.9 does not flush the operand cache
    and causes a kernel stack dump, which allows local
    users to obtain sensitive information from kernel
    memory and bypass the KASLR protection mechanism (in
    the kernel through 4.9) via a crafted ACPI
    table.(CVE-2017-13693)Linux kernel CIFS implementation,
    version 4.9.0 is vulnerable to a relative paths
    injection in directory entry lists.(CVE-2019-10220)A
    heap overflow flaw was found in the Linux kernel, all
    versions 3.x.x and 4.x.x before 4.18.0, in Marvell WiFi
    chip driver. The vulnerability allows a remote attacker
    to cause a system crash, resulting in a denial of
    service, or execute arbitrary code. The highest threat
    with this vulnerability is with the availability of the
    system. If code execution occurs, the code will run
    with the permissions of root. This will affect both
    confidentiality and integrity of files on the
    system.(CVE-2019-14901)In the AppleTalk subsystem in
    the Linux kernel before 5.1, there is a potential NULL
    pointer dereference because register_snap_client may
    return NULL. This will lead to denial of service in
    net/appletalk/aarp.c and net/appletalk/ddp.c, as
    demonstrated by unregister_snap_client, aka
    CID-9804501fa122.(CVE-2019-19227)In the Linux kernel
    before 5.2.10, there is a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/usb/class/cdc-acm.c driver, aka
    CID-c52873e5a1ef.(CVE-2019-19530)In the Linux kernel
    before 5.3.9, there are multiple out-of-bounds write
    bugs that can be caused by a malicious USB device in
    the Linux kernel HID drivers, aka CID-d9d4b1e46d95.
    This affects drivers/hid/hid-axff.c,
    drivers/hid/hid-dr.c, drivers/hid/hid-emsff.c,
    drivers/hid/hid-gaff.c, drivers/hid/hid-holtekff.c,
    drivers/hid/hid-lg2ff.c, drivers/hid/hid-lg3ff.c,
    drivers/hid/hid-lg4ff.c, drivers/hid/hid-lgff.c,
    drivers/hid/hid-logitech-hidpp.c,
    drivers/hid/hid-microsoft.c, drivers/hid/hid-sony.c,
    drivers/hid/hid-tmff.c, and
    drivers/hid/hid-zpff.c.(CVE-2019-19532)A use-after-free
    in binder.c allows an elevation of privilege from an
    application to the Linux Kernel. No user interaction is
    required to exploit this vulnerability, however
    exploitation does require either the installation of a
    malicious local application or a separate vulnerability
    in a network facing application.Product: AndroidAndroid
    ID: A-141720095(CVE-2019-2215)The do_remount function
    in fs/ namespace.c in the Linux kernel through 3.16.1
    does not maintain the MNT_LOCK_READONLY bit across a
    remount of a bind mount, which allows local users to
    bypass an intended read-only restriction and defeat
    certain sandbox protection mechanisms via a 'mount -o
    remount' command within a user
    namespace.(CVE-2014-5206)Multiple integer overflows in
    the lzo1x_decompress_safe function in
    lib/lzo/lzo1x_decompress_safe.c in the LZO decompressor
    in the Linux kernel before 3.15.2 allow
    context-dependent attackers to cause a denial of
    service (memory corruption) via a crafted Literal Run.
    NOTE: the author of the LZO algorithms says 'the Linux
    kernel is *not* affected media hype.'(CVE-2014-4608)The
    pivot_root implementation in fs/ namespace.c in the
    Linux kernel through 3.17 does not properly interact
    with certain locations of a chroot directory, which
    allows local users to cause a denial of service
    (mount-tree loop) via . (dot) values in both arguments
    to the pivot_root system call.(CVE-2014-7970)A security
    flaw was discovered in nl80211_set_rekey_data()
    function in the Linux kernel since v3.1-rc1 through
    v4.13. This function does not check whether the
    required attributes are present in a netlink request.
    This request can be issued by a user with CAP_NET_ADMIN
    privilege and may result in NULL dereference and a
    system crash.(CVE-2017-12153)arch/x86/kernel/entry_32.S
    in the Linux kernel through 3.15.1 on 32-bit x86
    platforms, when syscall auditing is enabled and the sep
    CPU feature flag is set, allows local users to cause a
    denial of service (OOPS and system crash) via an
    invalid syscall number, as demonstrated by number
    1000.(CVE-2014-4508)fs/ namespace.c in the Linux kernel
    through 3.16.1 does not properly restrict clearing
    MNT_NODEV, MNT_NOSUID, and MNT_NOEXEC and changing
    MNT_ATIME_MASK during a remount of a bind mount, which
    allows local users to gain privileges, interfere with
    backups and auditing on systems that had atime enabled,
    or cause a denial of service (excessive filesystem
    updating) on systems that had atime disabled via a
    'mount -o remount' command within a user
    namespace.(CVE-2014-5207)In the Linux kernel before
    5.3.7, there is a use-after-free bug that can be caused
    by a malicious USB device in the
    drivers/usb/misc/adutux.c driver, aka
    CID-44efc269db79.(CVE-2019-19523)In the Linux kernel
    before 5.3.12, there is a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/input/ff-memless.c driver, aka
    CID-fa3a5a1880c9.(CVE-2019-19524)In the Linux kernel
    before 5.2.10, there is a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/hid/usbhid/hiddev.c driver, aka
    CID-9c09b214f30e.(CVE-2019-19527)In the Linux kernel
    before 5.3.7, there is a use-after-free bug that can be
    caused by a malicious USB device in the
    drivers/usb/misc/iowarrior.c driver, aka
    CID-edc4746f253d.(CVE-2019-19528)In the Linux kernel
    before 5.2.9, there is a use-after-free bug that can be
    caused by a malicious USB device in the
    drivers/usb/misc/yurex.c driver, aka
    CID-fc05481b2fca.(CVE-2019-19531)In the Linux kernel
    before 5.3.4, there is an info-leak bug that can be
    caused by a malicious USB device in the
    drivers/media/usb/ttusb-dec/ttusb_dec.c driver, aka
    CID-a10feaf8c464.(CVE-2019-19533)In the Linux kernel
    before 5.3.11, there is an info-leak bug that can be
    caused by a malicious USB device in the drivers/
    net/can/usb/peak_usb/pcan_usb_core.c driver, aka
    CID-f7a1337f0d29..(CVE-2019-19534)In the Linux kernel
    before 5.2.9, there is an info-leak bug that can be
    caused by a malicious USB device in the drivers/
    net/can/usb/peak_usb/pcan_usb_pro.c driver, aka
    CID-ead16e53c2f0.(CVE-2019-19536)In the Linux kernel
    before 5.2.10, there is a race condition bug that can
    be caused by a malicious USB device in the USB
    character device driver layer, aka CID-303911cfc5b9.
    This affects drivers/usb/core/file.c.(CVE-2019-19537)A
    memory leak in the cx23888_ir_probe() function in
    drivers/media/pci/cx23885/cx23888-ir.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    kfifo_alloc() failures, aka
    CID-a7b2df76b42b.(CVE-2019-19054)A memory leak in the
    mwifiex_pcie_alloc_cmdrsp_buf() function in drivers/
    net/wireless/marvell/mwifiex/pcie.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    mwifiex_map_pci_memory() failures, aka
    CID-db8fd2cde932.(CVE-2019-19056)Two memory leaks in
    the mwifiex_pcie_init_evt_ring() function in drivers/
    net/wireless/marvell/mwifiex/pcie.c in the Linux kernel
    through 5.3.11 allow attackers to cause a denial of
    service (memory consumption) by triggering
    mwifiex_map_pci_memory() failures, aka
    CID-d10dcb615c8e.(CVE-2019-19057)A memory leak in the
    adis_update_scan_mode() function in
    drivers/iio/imu/adis_buffer.c in the Linux kernel
    before 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-ab612b1daf41.(CVE-2019-19060)A memory leak in the
    crypto_report() function in crypto/crypto_user_base.c
    in the Linux kernel through 5.3.11 allows attackers to
    cause a denial of service (memory consumption) by
    triggering crypto_report_alg() failures, aka
    CID-ffdde5932042.(CVE-2019-19062)Two memory leaks in
    the rtl_usb_probe() function in drivers/
    net/wireless/realtek/rtlwifi/usb.c in the Linux kernel
    through 5.3.11 allow attackers to cause a denial of
    service (memory consumption), aka
    CID-3f9361695113.(CVE-2019-19063)A memory leak in the
    bfad_im_get_stats() function in
    drivers/scsi/bfa/bfad_attr.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    bfa_port_get_stats() failures, aka
    CID-0e62395da2bd.(CVE-2019-19066)Memory leaks in
    drivers/ net/wireless/ath/ath9k/htc_hst.c in the Linux
    kernel through 5.3.11 allow attackers to cause a denial
    of service (memory consumption) by triggering
    wait_for_completion_timeout() failures. This affects
    the htc_config_pipe_credits() function, the
    htc_setup_complete() function, and the
    htc_connect_service() function, aka
    CID-853acf7caf10.(CVE-2019-19073)A memory leak in the
    ath9k_wmi_cmd() function in drivers/
    net/wireless/ath/ath9k/wmi.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-728c1e2a05e4.(CVE-2019-19074)An issue was
    discovered in fs/xfs/xfs_icache.c in the Linux kernel
    through 4.17.3. There is a NULL pointer dereference and
    panic in lookup_slow() on a NULL inode->i_ops pointer
    when doing pathwalks on a corrupted xfs image. This
    occurs because of a lack of proper validation that
    cached inodes are free during
    allocation.(CVE-2018-13093)An issue was discovered in
    slc_bump in drivers/ net/can/slcan.c in the Linux
    kernel through 5.6.2. It allows attackers to read
    uninitialized can_frame data, potentially containing
    sensitive information from kernel stack memory, if the
    configuration lacks CONFIG_INIT_STACK_ALL, aka
    CID-b9258a2cece4.(CVE-2020-11494)An issue was
    discovered in the Linux kernel through 5.6.2.
    mpol_parse_str in mm/mempolicy.c has a stack-based
    out-of-bounds write because an empty nodelist is
    mishandled during mount option parsing, aka
    CID-aa9f7d5172fa. NOTE: Someone in the security
    community disagrees that this is a vulnerability
    because the issue 'is a bug in parsing mount options
    which can only be specified by a privileged user, so
    triggering the bug does not grant any powers not
    already held.'.(CVE-2020-11565)In the Linux kernel
    before 5.4.12, drivers/input/input.c has out-of-bounds
    writes via a crafted keycode table, as demonstrated by
    input_set_keycode, aka
    CID-cb222aed03d7.(CVE-2019-20636)An issue was
    discovered in the Linux kernel before 5.6.1.
    drivers/media/usb/gspca/ov519.c allows NULL pointer
    dereferences in ov511_mode_init_regs and
    ov518_mode_init_regs when there are zero endpoints, aka
    CID-998912346c0d.(CVE-2020-11608)An issue was
    discovered in the stv06xx subsystem in the Linux kernel
    before 5.6.1. drivers/media/usb/gspca/stv06xx/stv06xx.c
    and drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c
    mishandle invalid descriptors, as demonstrated by a
    NULL pointer dereference, aka
    CID-485b06aadb93.(CVE-2020-11609)In the Linux kernel
    before 5.6.1, drivers/media/usb/gspca/xirlink_cit.c
    (aka the Xirlink camera USB driver) mishandles invalid
    descriptors, aka CID-a246b4d54770.(CVE-2020-11668)A
    flaw was found in the Linux kernel's implementation of
    GRO. This flaw allows an attacker with local access to
    crash the
    system.(CVE-2020-10720)gadget_dev_desc_UDC_store in
    drivers/usb/gadget/configfs.c in the Linux kernel
    through 5.6.13 relies on kstrdup without considering
    the possibility of an internal '\0' value, which allows
    attackers to trigger an out-of-bounds read, aka
    CID-15753588bcd4.(CVE-2020-13143)An issue was
    discovered in the Linux kernel through 5.6.11. sg_write
    lacks an sg_remove_request call in a certain failure
    case, aka CID-83c6f2390040.(CVE-2020-12770)A signal
    access-control issue was discovered in the Linux kernel
    before 5.6.5, aka CID-7395ea4e65c2. Because exec_id in
    include/linux/sched.h is only 32 bits, an integer
    overflow can interfere with a do_notify_parent
    protection mechanism. A child process can send an
    arbitrary signal to a parent process in a different
    security domain. Exploitation limitations include the
    amount of elapsed time before an integer overflow
    occurs, and the lack of scenarios where signals to a
    parent process present a substantial operational
    threat.(CVE-2020-12826)The fix for CVE-2019-11599,
    affecting the Linux kernel before 5.0.10 was not
    complete. A local user could use this flaw to obtain
    sensitive information, cause a denial of service, or
    possibly have other unspecified impacts by triggering a
    race condition with mmget_not_zero or get_task_mm
    calls.(CVE-2019-14898)usb_sg_cancel in
    drivers/usb/core/message.c in the Linux kernel before
    5.6.8 has a use-after-free because a transfer occurs
    without a reference, aka
    CID-056ad39ee925.(CVE-2020-12464)The __mptctl_ioctl
    function in drivers/message/fusion/mptctl.c in the
    Linux kernel before 5.4.14 allows local users to hold
    an incorrect lock during the ioctl operation and
    trigger a race condition, i.e., a 'double fetch'
    vulnerability, aka CID-28d76df18f0a. NOTE: the vendor
    states 'The security impact of this bug is not as bad
    as it could have been because these operations are all
    privileged and root already has enormous destructive
    power.'(CVE-2020-12652)An issue was found in Linux
    kernel before 5.5.4. The mwifiex_cmd_append_vsie_tlv()
    function in drivers/
    net/wireless/marvell/mwifiex/scan.c allows local users
    to gain privileges or cause a denial of service because
    of an incorrect memcpy and buffer overflow, aka
    CID-b70261a288ea.(CVE-2020-12653)An issue was found in
    Linux kernel before 5.5.4. mwifiex_ret_wmm_get_status()
    in drivers/ net/wireless/marvell/mwifiex/wmm.c allows a
    remote AP to trigger a heap-based buffer overflow
    because of an incorrect memcpy, aka
    CID-3a9b153c5591.(CVE-2020-12654)An issue was
    discovered in xfs_agf_verify in
    fs/xfs/libxfs/xfs_alloc.c in the Linux kernel through
    5.6.10. Attackers may trigger a sync of excessive
    duration via an XFS v5 image with crafted metadata, aka
    CID-d0c7feaf8767.(CVE-2020-12655)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1674
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35c58a13");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14901");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android Binder Use-After-Free Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-327.62.59.83.h230",
        "kernel-debug-3.10.0-327.62.59.83.h230",
        "kernel-debug-devel-3.10.0-327.62.59.83.h230",
        "kernel-debuginfo-3.10.0-327.62.59.83.h230",
        "kernel-debuginfo-common-x86_64-3.10.0-327.62.59.83.h230",
        "kernel-devel-3.10.0-327.62.59.83.h230",
        "kernel-headers-3.10.0-327.62.59.83.h230",
        "kernel-tools-3.10.0-327.62.59.83.h230",
        "kernel-tools-libs-3.10.0-327.62.59.83.h230",
        "perf-3.10.0-327.62.59.83.h230",
        "python-perf-3.10.0-327.62.59.83.h230"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
