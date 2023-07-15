#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136239);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2019-10220",
    "CVE-2019-11135",
    "CVE-2019-11191",
    "CVE-2019-14895",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-14901",
    "CVE-2019-16229",
    "CVE-2019-16231",
    "CVE-2019-16232",
    "CVE-2019-19036",
    "CVE-2019-19037",
    "CVE-2019-19039",
    "CVE-2019-19060",
    "CVE-2019-19227",
    "CVE-2019-19252",
    "CVE-2019-19332",
    "CVE-2019-19338",
    "CVE-2019-19447",
    "CVE-2019-19524",
    "CVE-2019-19525",
    "CVE-2019-19526",
    "CVE-2019-19527",
    "CVE-2019-19529",
    "CVE-2019-19532",
    "CVE-2019-19534",
    "CVE-2019-19535",
    "CVE-2019-19536",
    "CVE-2019-19767",
    "CVE-2019-19768",
    "CVE-2019-19770",
    "CVE-2019-19807",
    "CVE-2019-19815",
    "CVE-2019-19922",
    "CVE-2019-19927",
    "CVE-2019-19947",
    "CVE-2019-20095",
    "CVE-2019-20096",
    "CVE-2019-20636",
    "CVE-2019-3016",
    "CVE-2019-5108",
    "CVE-2020-0067",
    "CVE-2020-10720",
    "CVE-2020-11494",
    "CVE-2020-11565",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-11668",
    "CVE-2020-11669",
    "CVE-2020-14331",
    "CVE-2020-1749",
    "CVE-2020-2732",
    "CVE-2020-8428",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-9383"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : kernel (EulerOS-SA-2020-1536)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc. Security Fix(es):In the Linux kernel
    before 5.2.9, there is an info-leak bug that can be
    caused by a malicious USB device in the
    driverset/can/usb/peak_usb/pcan_usb_pro.c driver, aka
    CID-ead16e53c2f0.(CVE-2019-19536)In the Linux kernel
    before 5.2.9, there is an info-leak bug that can be
    caused by a malicious USB device in the
    driverset/can/usb/peak_usb/pcan_usb_fd.c driver, aka
    CID-30a8beeb3042.(CVE-2019-19535)vcs_write in
    drivers/tty/vt/vc_screen.c in the Linux kernel through
    5.3.13 does not prevent write access to vcsu devices,
    aka CID-0c9acb1af77a.(CVE-2019-19252)In the AppleTalk
    subsystem in the Linux kernel before 5.1, there is a
    potential NULL pointer dereference because
    register_snap_client may return NULL. This will lead to
    denial of service in net/appletalk/aarp.c and
    net/appletalk/ddp.c, as demonstrated by
    unregister_snap_client, aka
    CID-9804501fa122.(CVE-2019-19227)A memory leak in the
    adis_update_scan_mode() function in
    drivers/iio/imu/adis_buffer.c in the Linux kernel
    before 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-ab612b1daf41.(CVE-2019-19060)In the Linux kernel
    before 5.3.11, there is an info-leak bug that can be
    caused by a malicious USB device in the
    driverset/can/usb/peak_usb/pcan_usb_core.c driver, aka
    CID-f7a1337f0d29.(CVE-2019-19534)In the Linux kernel
    before 5.3.11, there is a use-after-free bug that can
    be caused by a malicious USB device in the
    driverset/can/usb/mcba_usb.c driver, aka
    CID-4d6636498c41.(CVE-2019-19529)In the Linux kernel
    before 5.3.9, there is a use-after-free bug that can be
    caused by a malicious USB device in the
    driversfc/pn533/usb.c driver, aka
    CID-6af3aa57a098.(CVE-2019-19526)In the Linux kernel
    before 5.3.6, there is a use-after-free bug that can be
    caused by a malicious USB device in the
    driverset/ieee802154/atusb.c driver, aka
    CID-7fd25e6fc035.(CVE-2019-19525)In the Linux kernel
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
    drivers/hid/hid-zpff.c.(CVE-2019-19532)In the Linux
    kernel before 5.2.10, there is a use-after-free bug
    that can be caused by a malicious USB device in the
    drivers/hid/usbhid/hiddev.c driver, aka
    CID-9c09b214f30e.(CVE-2019-19527)** DISPUTED ** The
    Linux kernel through 5.0.7, when CONFIG_IA32_AOUT is
    enabled and ia32_aout is loaded, allows local users to
    bypass ASLR on setuid a.out programs (if any exist)
    because install_exec_creds() is called too late in
    load_aout_binary() in fs/binfmt_aout.c, and thus the
    ptrace_may_access() check has a race condition when
    reading /proc/pid/stat. NOTE: the software maintainer
    disputes that this is a vulnerability because ASLR for
    a.out format executables has never been
    supported.(CVE-2019-11191)In the Linux kernel before
    5.3.12, there is a use-after-free bug that can be
    caused by a malicious USB device in the
    drivers/input/ff-memless.c driver, aka
    CID-fa3a5a1880c9.(CVE-2019-19524)driverset/wireless/mar
    vell/libertas/if_sdio.c in the Linux kernel 5.2.14 does
    not check the alloc_workqueue return value, leading to
    a NULL pointer
    dereference.(CVE-2019-16232)driverset/fjes/fjes_main.c
    in the Linux kernel 5.2.14 does not check the
    alloc_workqueue return value, leading to a NULL pointer
    dereference.(CVE-2019-16231)** DISPUTED **
    drivers/gpu/drm/amd/amdkfd/kfd_interrupt.c in the Linux
    kernel 5.2.14 does not check the alloc_workqueue return
    value, leading to a NULL pointer dereference. NOTE: The
    security community disputes this issues as not being
    serious enough to be deserving a CVE
    id.(CVE-2019-16229)Linux kernel CIFS implementation,
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
    system.(CVE-2019-14901)The Linux kernel before 5.4.2
    mishandles ext4_expand_extra_isize, as demonstrated by
    use-after-free errors in __ext4_expand_extra_isize and
    ext4_xattr_set_entry, related to fs/ext4/inode.c and
    fs/ext4/super.c, aka CID-4ea99936a163.(CVE-2019-19767)A
    heap-based buffer overflow was discovered in the Linux
    kernel, all versions 3.x.x and 4.x.x before 4.18.0, in
    Marvell WiFi chip driver. The flaw could occur when the
    station attempts a connection negotiation during the
    handling of the remote devices country settings. This
    could allow the remote device to cause a denial of
    service (system crash) or possibly execute arbitrary
    code.(CVE-2019-14895)Linux Kernel could allow a local
    authenticated attacker to obtain sensitive information,
    caused by a Transaction Asynchronous Abort (TAA) h/w
    issue in KVM. By sending a specially-crafted request,
    an attacker could exploit this vulnerability to obtain
    sensitive information, and use this information to
    launch further attacks against the affected
    system.(CVE-2019-19338)TSX Asynchronous Abort condition
    on some CPUs utilizing speculative execution may allow
    an authenticated user to potentially enable information
    disclosure via a side channel with local
    access.(CVE-2019-11135)An out-of-bounds memory write
    issue was found in the Linux Kernel, version 3.13
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
    execution.)(CVE-2019-19922)A stack-based buffer
    overflow was found in the Linux kernel, version
    kernel-2.6.32, in Marvell WiFi chip driver. An attacker
    is able to cause a denial of service (system crash) or,
    possibly execute arbitrary code, when a STA works in
    IBSS mode (allows connecting stations together without
    the use of an AP) and connects to another
    STA.(CVE-2019-14897)A heap-based buffer overflow
    vulnerability was found in the Linux kernel, version
    kernel-2.6.32, in Marvell WiFi chip driver. A remote
    attacker could cause a denial of service (system crash)
    or, possibly execute arbitrary code, when the
    lbs_ibss_join_existing function is called after a STA
    connects to an AP.(CVE-2019-14896)In the Linux kernel
    through 5.4.6, there are information leaks of
    uninitialized memory to a USB device in the
    driverset/can/usb/kvaser_usb/kvaser_usb_leaf.c driver,
    aka CID-da2311a6385c.(CVE-2019-19947)In the Linux
    kernel before 5.1, there is a memory leak in
    __feat_register_sp() in net/dccp/feat.c, which may
    cause denial of service, aka
    CID-1d3ff0950e2b.(CVE-2019-20096)mwifiex_tm_cmd in
    driverset/wireless/marvell/mwifiex/cfg80211.c in the
    Linux kernel before 5.1.6 has some error-handling cases
    that did not free allocated hostcmd memory, aka
    CID-003b686ace82. This will cause a memory leak and
    denial of service.(CVE-2019-20095)An exploitable
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
    vulnerability.(CVE-2019-5108)In a Linux KVM guest that
    has PV TLB enabled, a process in the guest kernel may
    be able to read memory locations from another process
    in the same guest. This problem is limit to the host
    running linux kernel 4.10 with a guest running linux
    kernel 4.16 or later. The problem mainly affects AMD
    processors but Intel CPUs cannot be ruled
    out.(CVE-2019-3016)fsamei.c in the Linux kernel before
    5.5 has a may_create_in_sticky use-after-free, which
    allows local users to cause a denial of service (OOPS)
    or possibly obtain sensitive information from kernel
    memory, aka CID-d0cb50185ae9. One attack vector may be
    an open system call for a UNIX domain socket, if the
    socket is being moved to a new parent directory and its
    old parent directory is being
    removed.(CVE-2020-8428)There is a use-after-free
    vulnerability in the Linux kernel through 5.5.2 in the
    n_tty_receive_buf_common function in
    drivers/tty_tty.c.(CVE-2020-8648)An issue was
    discovered in the Linux kernel through 5.5.6. set_fdc
    in drivers/block/floppy.c leads to a wait_til_ready
    out-of-bounds read because the FDC index is not checked
    for errors before assigning it, aka
    CID-2e90ca68b0d2.(CVE-2020-9383)There is a
    use-after-free vulnerability in the Linux kernel
    through 5.5.2 in the vgacon_invert_region function in
    drivers/video/console/vgacon.c.(CVE-2020-8649)There is
    a use-after-free vulnerability in the Linux kernel
    through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c.(CVE-2020-8647)In the Linux kernel
    5.0.21, mounting a crafted ext4 filesystem image,
    performing some operations, and unmounting can lead to
    a use-after-free in ext4_put_super in fs/ext4/super.c,
    related to dump_orphan_list in
    fs/ext4/super.c.(CVE-2019-19447)A flaw was discovered
    in the way that the KVM hypervisor handled instruction
    emulation for an L2 guest when nested virtualisation is
    enabled. Under some circumstances, an L2 guest may
    trick the L0 guest into accessing sensitive L1
    resources that should be inaccessible to the L2
    guest.(CVE-2020-2732)In the Linux kernel before 5.3.11,
    sound/core/timer.c has a use-after-free caused by
    erroneous code refactoring, aka CID-e7af6307a8a5. This
    is related to snd_timer_open and
    snd_timer_close_locked. The timeri variable was
    originally intended to be for a newly created timer
    instance, but was used for a different purpose after
    refactoring.(CVE-2019-19807)In the Linux kernel
    5.4.0-rc2, there is a use-after-free (read) in the
    __blk_add_trace function in kernel/trace/blktrace.c
    (which is used to fill out a blk_io_trace structure and
    place it in a per-cpu sub-buffer).(CVE-2019-19768)In
    the Linux kernel 5.0.21, mounting a crafted f2fs
    filesystem image can cause a NULL pointer dereference
    in f2fs_recover_fsync_data in fs/f2fs/recovery.c. This
    is related to F2FS_P_SB in
    fs/f2fs/f2fs.h.(CVE-2019-19815)** DISPUTED **
    __btrfs_free_extent in fs/btrfs/extent-tree.c in the
    Linux kernel through 5.3.12 calls btrfs_print_leaf in a
    certain ENOENT case, which allows local users to obtain
    potentially sensitive information about register values
    via the dmesg program. NOTE: The BTRFS development team
    disputes this issues as not being a vulnerability
    because '1) The kernel provide facilities to restrict
    access to dmesg - dmesg_restrict=1 sysctl option. So
    it's really up to the system administrator to judge
    whether dmesg access shall be disallowed or not. 2)
    WARN/WARN_ON are widely used macros in the linux
    kernel. If this CVE is considered valid this would mean
    there are literally thousands CVE lurking in the kernel
    - something which clearly is not the
    case.'(CVE-2019-19039)ext4_empty_dir in fs/ext4amei.c
    in the Linux kernel through 5.3.12 allows a NULL
    pointer dereference because
    ext4_read_dirblock(inode,0,DIRENT_HTREE) can be
    zero.(CVE-2019-19037)btrfs_root_node in
    fs/btrfs/ctree.c in the Linux kernel through 5.3.12
    allows a NULL pointer dereference because
    rcu_dereference(root->node) can be
    zero.(CVE-2019-19036)In the Linux kernel 4.19.83, there
    is a use-after-free (read) in the debugfs_remove
    function in fs/debugfs/inode.c (which is used to remove
    a file or directory in debugfs that was previously
    created with a call to another debugfs function such as
    debugfs_create_file).(CVE-2019-19770)An issue was
    discovered in slc_bump in driverset/can/slcan.c in the
    Linux kernel through 5.6.2. It allows attackers to read
    uninitialized can_frame data, potentially containing
    sensitive information from kernel stack memory, if the
    configuration lacks CONFIG_INIT_STACK_ALL, aka
    CID-b9258a2cece4.(CVE-2020-11494)An issue was
    discovered in the Linux kernel through 5.6.2.
    mpol_parse_str in mm/mempolicy.c has a stack-based
    out-of-bounds write because an empty nodelist is
    mishandled during mount option parsing, aka
    CID-aa9f7d5172fa.(CVE-2020-11565)A flaw was found in
    the Linux kernel's implementation of some networking
    protocols in IPsec, such as VXLAN and GENEVE tunnels
    over IPv6. When an encrypted tunnel is created between
    two hosts, the kernel isn't correctly routing tunneled
    data over the encrypted link rather sending the data
    unencrypted. This would allow anyone in between the two
    endpoints to read the traffic unencrypted. The main
    threat from this vulnerability is to data
    confidentiality.(CVE-2020-1749)An issue was discovered
    in the stv06xx subsystem in the Linux kernel before
    5.6.1. drivers/media/usb/gspca/stv06xx/stv06xx.c and
    drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c
    mishandle invalid descriptors, as demonstrated by a
    NULL pointer dereference, aka
    CID-485b06aadb93.(CVE-2020-11609)An issue was
    discovered in the Linux kernel before 5.6.1.
    drivers/media/usb/gspca/ov519.c allows NULL pointer
    dereferences in ov511_mode_init_regs and
    ov518_mode_init_regs when there are zero endpoints, aka
    CID-998912346c0d.(CVE-2020-11608)In the Linux kernel
    before 5.4.12, drivers/input/input.c has out-of-bounds
    writes via a crafted keycode table, as demonstrated by
    input_set_keycode, aka
    CID-cb222aed03d7.(CVE-2019-20636)In the Linux kernel
    before 5.6.1, drivers/media/usb/gspca/xirlink_cit.c
    (aka the Xirlink camera USB driver) mishandles invalid
    descriptors, aka CID-a246b4d54770.(CVE-2020-11668)An
    issue was discovered in the Linux kernel through 5.6.2.
    mpol_parse_str in mm/mempolicy.c has a stack-based
    out-of-bounds write because an empty nodelist is
    mishandled during mount option parsing, aka
    CID-aa9f7d5172fa.(CVE-2020-0067)An issue was discovered
    in the Linux kernel before 5.2 on the powerpc platform.
    arch/powerpc/kernel/idle_book3s.S does not have
    save/restore functionality for PNV_POWERSAVE_AMR,
    PNV_POWERSAVE_UAMOR, and PNV_POWERSAVE_AMOR, aka
    CID-53a712bae5dd.(CVE-2020-11669)A flaw was found in
    the Linux kernelaEUR?s implementation of GRO. This flaw
    allows an attacker with local access to crash the
    system.(CVE-2020-10720)A flaw was found in the Linux
    kernel's implementation of the invert video code on VGA
    consoles when a local attacker attempts to resize the
    console, calling an ioctl VT_RESIZE, which causes an
    out-of-bounds write to occur. This flaw allows a local
    user with access to the VGA console to crash the
    system, potentially escalating their privileges on the
    system. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system
    availability.(CVE-2020-14331)An out-of-bounds (OOB)
    memory access flaw was found in ttm_put_pages in
    drivers/gpu/drm/ttm/ttm_page_alloc.c in the Linux
    kernel's graphics module. Incrementing the page pointer
    for huge pages was not in sync with the reference
    counter, and this could lead to an out-of-bounds access
    or a denial of service. This flaw allows a local
    attacker with special user privileges (or root) to
    cause memory exploitation.(CVE-2019-19927)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1536
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a90e7d8e");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-vhulk1907.1.0.h729",
        "kernel-devel-4.19.36-vhulk1907.1.0.h729",
        "kernel-headers-4.19.36-vhulk1907.1.0.h729",
        "kernel-tools-4.19.36-vhulk1907.1.0.h729",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h729",
        "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h729",
        "perf-4.19.36-vhulk1907.1.0.h729",
        "python-perf-4.19.36-vhulk1907.1.0.h729"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
