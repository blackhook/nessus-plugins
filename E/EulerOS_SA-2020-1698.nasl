#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137805);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2019-19036",
    "CVE-2019-19037",
    "CVE-2019-19039",
    "CVE-2019-19377",
    "CVE-2019-19462",
    "CVE-2019-19770",
    "CVE-2019-19815",
    "CVE-2019-20636",
    "CVE-2019-20806",
    "CVE-2020-0067",
    "CVE-2020-1749",
    "CVE-2020-10711",
    "CVE-2020-10942",
    "CVE-2020-11494",
    "CVE-2020-11565",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-11668",
    "CVE-2020-11669",
    "CVE-2020-12114",
    "CVE-2020-12464",
    "CVE-2020-12465",
    "CVE-2020-12652",
    "CVE-2020-12653",
    "CVE-2020-12654",
    "CVE-2020-12655",
    "CVE-2020-12659",
    "CVE-2020-12770",
    "CVE-2020-12771",
    "CVE-2020-12826",
    "CVE-2020-13143"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : kernel (EulerOS-SA-2020-1698)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - In the Linux kernel 5.0.21, mounting a crafted f2fs
    filesystem image can cause a NULL pointer dereference
    in f2fs_recover_fsync_data in fs/f2fs/recovery.c. This
    is related to F2FS_P_SB in
    fs/f2fs/f2fs.h.(CVE-2019-19815)

  - ** DISPUTED ** __btrfs_free_extent in
    fs/btrfs/extent-tree.c in the Linux kernel through
    5.3.12 calls btrfs_print_leaf in a certain ENOENT case,
    which allows local users to obtain potentially
    sensitive information about register values via the
    dmesg program. NOTE: The BTRFS development team
    disputes this issues as not being a vulnerability
    because '1) The kernel provide facilities to restrict
    access to dmesg - dmesg_restrict=1 sysctl option. So
    it's really up to the system administrator to judge
    whether dmesg access shall be disallowed or not. 2)
    WARN/WARN_ON are widely used macros in the linux
    kernel. If this CVE is considered valid this would mean
    there are literally thousands CVE lurking in the kernel
    - something which clearly is not the
    case.'(CVE-2019-19039)

  - ext4_empty_dir in fs/ext4/namei.c in the Linux kernel
    through 5.3.12 allows a NULL pointer dereference
    because ext4_read_dirblock(inode,0,DIRENT_HTREE) can be
    zero.(CVE-2019-19037)

  - btrfs_root_node in fs/btrfs/ctree.c in the Linux kernel
    through 5.3.12 allows a NULL pointer dereference
    because rcu_dereference(root->node) can be
    zero.(CVE-2019-19036)

  - ** DISPUTED ** In the Linux kernel 4.19.83, there is a
    use-after-free (read) in the debugfs_remove function in
    fs/debugfs/inode.c (which is used to remove a file or
    directory in debugfs that was previously created with a
    call to another debugfs function such as
    debugfs_create_file). NOTE: Linux kernel developers
    dispute this issue as not being an issue with debugfs,
    instead this is an issue with misuse of debugfs within
    blktrace.(CVE-2019-19770)

  - An issue was discovered in slc_bump in
    drivers/net/can/slcan.c in the Linux kernel through
    5.6.2. It allows attackers to read uninitialized
    can_frame data, potentially containing sensitive
    information from kernel stack memory, if the
    configuration lacks CONFIG_INIT_STACK_ALL, aka
    CID-b9258a2cece4.(CVE-2020-11494)

  - ** DISPUTED ** An issue was discovered in the Linux
    kernel through 5.6.2. mpol_parse_str in mm/mempolicy.c
    has a stack-based out-of-bounds write because an empty
    nodelist is mishandled during mount option parsing, aka
    CID-aa9f7d5172fa. NOTE: Someone in the security
    community disagrees that this is a vulnerability
    because the issue 'is a bug in parsing mount options
    which can only be specified by a privileged user, so
    triggering the bug does not grant any powers not
    already held.'.(CVE-2020-11565)

  - A flaw was found in the Linux kernel's implementation
    of some networking protocols in IPsec, such as VXLAN
    and GENEVE tunnels over IPv6. When an encrypted tunnel
    is created between two hosts, the kernel isn't
    correctly routing tunneled data over the encrypted link
    rather sending the data unencrypted. This would allow
    anyone in between the two endpoints to read the traffic
    unencrypted. The main threat from this vulnerability is
    to data confidentiality.(CVE-2020-1749)

  - An issue was discovered in the stv06xx subsystem in the
    Linux kernel before 5.6.1.
    drivers/media/usb/gspca/stv06xx/stv06xx.c and
    drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c
    mishandle invalid descriptors, as demonstrated by a
    NULL pointer dereference, aka
    CID-485b06aadb93.(CVE-2020-11609)

  - An issue was discovered in the Linux kernel before
    5.6.1. drivers/media/usb/gspca/ov519.c allows NULL
    pointer dereferences in ov511_mode_init_regs and
    ov518_mode_init_regs when there are zero endpoints, aka
    CID-998912346c0d.(CVE-2020-11608)

  - In the Linux kernel before 5.4.12,
    drivers/input/input.c has out-of-bounds writes via a
    crafted keycode table, as demonstrated by
    input_set_keycode, aka
    CID-cb222aed03d7.(CVE-2019-20636)

  - In the Linux kernel before 5.6.1,
    drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink
    camera USB driver) mishandles invalid descriptors, aka
    CID-a246b4d54770.(CVE-2020-11668)

  - In f2fs_xattr_generic_list of xattr.c, there is a
    possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure
    with System execution privileges needed. User
    interaction is not required for exploitation.Product:
    Android. Versions: Android kernel. Android ID:
    A-120551147.(CVE-2020-0067)

  - An issue was discovered in the Linux kernel before 5.2
    on the powerpc platform.
    arch/powerpc/kernel/idle_book3s.S does not have
    save/restore functionality for PNV_POWERSAVE_AMR,
    PNV_POWERSAVE_UAMOR, and PNV_POWERSAVE_AMOR, aka
    CID-53a712bae5dd.(CVE-2020-11669)

  - In the Linux kernel before 5.5.8, get_raw_socket in
    drivers/vhost/net.c lacks validation of an sk_family
    field, which might allow attackers to trigger kernel
    stack corruption via crafted system
    calls.(CVE-2020-10942)

  - In the Linux kernel 5.0.21, mounting a crafted btrfs
    filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in
    btrfs_queue_work in
    fs/btrfs/async-thread.c.(CVE-2019-19377)

  - relay_open in kernel/relay.c in the Linux kernel
    through 5.4.1 allows local users to cause a denial of
    service (such as relay blockage) by triggering a NULL
    alloc_percpu result.(CVE-2019-19462)

  - An issue was discovered in xfs_agf_verify in
    fs/xfs/libxfs/xfs_alloc.c in the Linux kernel through
    5.6.10. Attackers may trigger a sync of excessive
    duration via an XFS v5 image with crafted metadata, aka
    CID-d0c7feaf8767.(CVE-2020-12655)

  - The __mptctl_ioctl function in
    drivers/message/fusion/mptctl.c in the Linux kernel
    before 5.4.14 allows local users to hold an incorrect
    lock during the ioctl operation and trigger a race
    condition, i.e., a 'double fetch' vulnerability, aka
    CID-28d76df18f0a. NOTE: the vendor states 'The security
    impact of this bug is not as bad as it could have been
    because these operations are all privileged and root
    already has enormous destructive
    power.'(CVE-2020-12652)

  - A pivot_root race condition in fs/namespace.c in the
    Linux kernel 4.4.x before 4.4.221, 4.9.x before
    4.9.221, 4.14.x before 4.14.178, 4.19.x before
    4.19.119, and 5.x before 5.3 allows local users to
    cause a denial of service (panic) by corrupting a
    mountpoint reference counter.(CVE-2020-12114)

  - usb_sg_cancel in drivers/usb/core/message.c in the
    Linux kernel before 5.6.8 has a use-after-free because
    a transfer occurs without a reference, aka
    CID-056ad39ee925.(CVE-2020-12464)

  - An issue was found in Linux kernel before 5.5.4.
    mwifiex_ret_wmm_get_status() in
    drivers/net/wireless/marvell/mwifiex/wmm.c allows a
    remote AP to trigger a heap-based buffer overflow
    because of an incorrect memcpy, aka
    CID-3a9b153c5591.(CVE-2020-12654)

  - An issue was found in Linux kernel before 5.5.4. The
    mwifiex_cmd_append_vsie_tlv() function in
    drivers/net/wireless/marvell/mwifiex/scan.c allows
    local users to gain privileges or cause a denial of
    service because of an incorrect memcpy and buffer
    overflow, aka CID-b70261a288ea.(CVE-2020-12653)

  - An array overflow was discovered in mt76_add_fragment
    in drivers/net/wireless/mediatek/mt76/dma.c in the
    Linux kernel before 5.5.10, aka CID-b102f0c522cf. An
    oversized packet with too many rx fragments can corrupt
    memory of adjacent pages.(CVE-2020-12465)

  - An issue was discovered in the Linux kernel before
    5.6.7. xdp_umem_reg in net/xdp/xdp_umem.c has an
    out-of-bounds write (by a user with the CAP_NET_ADMIN
    capability) because of a lack of headroom
    validation.(CVE-2020-12659)

  - An issue was discovered in the Linux kernel through
    5.6.11. btree_gc_coalesce in drivers/md/bcache/btree.c
    has a deadlock if a coalescing operation
    fails.(CVE-2020-12771)

  - An issue was discovered in the Linux kernel through
    5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka
    CID-83c6f2390040.(CVE-2020-12770)

  - A signal access-control issue was discovered in the
    Linux kernel before 5.6.5, aka CID-7395ea4e65c2.
    Because exec_id in include/linux/sched.h is only 32
    bits, an integer overflow can interfere with a
    do_notify_parent protection mechanism. A child process
    can send an arbitrary signal to a parent process in a
    different security domain. Exploitation limitations
    include the amount of elapsed time before an integer
    overflow occurs, and the lack of scenarios where
    signals to a parent process present a substantial
    operational threat.(CVE-2020-12826)

  - A NULL pointer dereference flaw was found in the Linux
    kernel's SELinux subsystem in versions before 5.7. This
    flaw occurs while importing the Commercial IP Security
    Option (CIPSO) protocol's category bitmap into the
    SELinux extensible bitmap via the'
    ebitmap_netlbl_import' routine. While processing the
    CIPSO restricted bitmap tag in the
    'cipso_v4_parsetag_rbm' routine, it sets the security
    attribute to indicate that the category bitmap is
    present, even if it has not been allocated. This issue
    leads to a NULL pointer dereference issue while
    importing the same category bitmap into SELinux. This
    flaw allows a remote network user to crash the system
    kernel, resulting in a denial of
    service.(CVE-2020-10711)

  - gadget_dev_desc_UDC_store in
    drivers/usb/gadget/configfs.c in the Linux kernel
    through 5.6.13 relies on kstrdup without considering
    the possibility of an internal '\0' value, which allows
    attackers to trigger an out-of-bounds read, aka
    CID-15753588bcd4.(CVE-2020-13143)

  - An issue was discovered in the Linux kernel before 5.2.
    There is a NULL pointer dereference in
    tw5864_handle_frame() in
    drivers/media/pci/tw5864/tw5864-video.c, which may
    cause denial of service, aka
    CID-2e7682ebfc75.(CVE-2019-20806)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1698
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52f61197");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12659");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-vhulk1907.1.0.h753.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h753.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h753.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h753.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h753.eulerosv2r8",
        "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h753.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h753.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h753.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h753.eulerosv2r8"];

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
