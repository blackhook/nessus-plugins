#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149098);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/04");

  script_cve_id(
    "CVE-2014-7841",
    "CVE-2016-3857",
    "CVE-2016-8660",
    "CVE-2017-13305",
    "CVE-2017-17741",
    "CVE-2017-18216",
    "CVE-2017-7482",
    "CVE-2018-10322",
    "CVE-2018-10876",
    "CVE-2018-10877",
    "CVE-2018-10880",
    "CVE-2018-10902",
    "CVE-2018-13093",
    "CVE-2018-14734",
    "CVE-2018-16276",
    "CVE-2018-7492",
    "CVE-2018-9383",
    "CVE-2019-11486",
    "CVE-2019-11815",
    "CVE-2019-12614",
    "CVE-2019-19319",
    "CVE-2019-6974",
    "CVE-2019-7221",
    "CVE-2020-0404",
    "CVE-2020-0427",
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-25656",
    "CVE-2020-25669",
    "CVE-2020-27777",
    "CVE-2020-27815",
    "CVE-2020-35519",
    "CVE-2020-36158",
    "CVE-2021-20261",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-28972",
    "CVE-2021-3178"
  );
  script_bugtraq_id(
    71081
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2021-1808)");
  script_summary(english:"Checks the rpm output for the updated packages.");

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
    output, etc.Security Fix(es):A flaw was found in Linux
    kernel in the ext4 filesystem code. A use-after-free is
    possible in ext4_ext_remove_space() function when
    mounting and operating a crafted ext4
    image.(CVE-2018-10876)A flaw was found in the Linux
    kernel. A use-after-free was found in the way the
    console subsystem was using ioctls KDGKBSENT and
    KDSKBSENT. A local user could use this flaw to get read
    memory access out of bounds. The highest threat from
    this vulnerability is to data
    confidentiality.(CVE-2020-25656)A flaw was found in the
    way RTAS handled memory accesses in userspace to kernel
    communication. On a locked down (usually due to Secure
    Boot) guest system running on top of PowerVM or KVM
    hypervisors (pseries platform) a root like local user
    could use this flaw to further increase their
    privileges to that of a running
    kernel.(CVE-2020-27777)A information disclosure
    vulnerability in the Upstream kernel encrypted-keys.
    Product: Android. Versions: Android kernel. Android ID:
    A-70526974.(CVE-2017-13305)A race condition was found
    in the Linux kernels implementation of the floppy disk
    drive controller driver software. The impact of this
    issue is lessened by the fact that the default
    permissions on the floppy device (/dev/fd0) are
    restricted to root. If the permissions on the device
    have changed the impact changes greatly. In the default
    configuration root (or equivalent) permissions are
    required to attack this flaw.(CVE-2021-20261)An issue
    was discovered in dlpar_parse_cc_property in
    arch/powerpc/platforms/pseries/dlpar.c in the Linux
    kernel through 5.1.6. There is an unchecked kstrdup of
    prop->name, which might allow an attacker to cause a
    denial of service (NULL pointer dereference and system
    crash).(CVE-2019-12614)An issue was discovered in
    fs/xfs/xfs_icache.c in the Linux kernel through 4.17.3.
    There is a NULL pointer dereference and panic in
    lookup_slow() on a NULL inode->i_ops pointer when doing
    pathwalks on a corrupted xfs image. This occurs because
    of a lack of proper validation that cached inodes are
    free during allocation.(CVE-2018-13093)An issue was
    discovered in rds_tcp_kill_sock in net/rds/tcp.c in the
    Linux kernel before 5.0.8. There is a race condition
    leading to a use-after-free, related to net namespace
    cleanup.(CVE-2019-11815)An issue was discovered in the
    Linux kernel through 5.11.3. A kernel pointer leak can
    be used to determine the address of the iscsi_transport
    structure. When an iSCSI transport is registered with
    the iSCSI subsystem, the transport's handle is
    available to unprivileged users via the sysfs file
    system, at
    /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When
    read, the show_transport_handle function (in
    drivers/scsi/scsi_transport_iscsi.c) is called, which
    leaks the handle. This handle is actually the pointer
    to an iscsi_transport struct in the kernel module's
    global variables.(CVE-2021-27363)An issue was
    discovered in the Linux kernel through 5.11.3. Certain
    iSCSI data structures do not have appropriate length
    constraints or checks, and can exceed the PAGE_SIZE
    value. An unprivileged user can send a Netlink message
    that is associated with iSCSI, and has a length up to
    the maximum length of a Netlink
    message.(CVE-2021-27365)An issue was discovered in the
    Linux kernel through 5.11.3.
    drivers/scsi/scsi_transport_iscsi.c is adversely
    affected by the ability of an unprivileged user to
    craft Netlink messages.(CVE-2021-27364)An issue was
    discovered in yurex_read in drivers/usb/misc/yurex.c in
    the Linux kernel before 4.17.7. Local attackers could
    use user access read/writes with incorrect bounds
    checking in the yurex USB driver to crash the kernel or
    potentially escalate
    privileges.(CVE-2018-16276)drivers/infiniband/core/ucma
    .c in the Linux kernel through 4.17.11 allows
    ucma_leave_multicast to access a certain data structure
    after a cleanup step in ucma_process_join, which allows
    attackers to cause a denial of service
    (use-after-free).(CVE-2018-14734)In create_pinctrl of
    core.c, there is a possible out of bounds read due to a
    use after free. This could lead to local information
    disclosure with no additional execution privileges
    needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-140550171(CVE-2020-0427)In
    do_epoll_ctl and ep_loop_check_proc of eventpoll.c,
    there is a possible use after free due to a logic
    error. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-147802478References: Upstream kernel(CVE-2020-0466)In
    fs/ocfs2/cluster/ nodemanager.c in the Linux kernel
    before 4.15, local users can cause a denial of service
    (NULL pointer dereference and BUG) because a required
    mutex is not used.(CVE-2017-18216)In the Linux kernel
    before 5.2, a setxattr operation, after a mount of a
    crafted ext4 image, can cause a slab-out-of-bounds
    write access because of an ext4_xattr_set_entry
    use-after-free in fs/ext4/xattr.c when a large old_size
    value is used in a memset call, aka
    CID-345c0dbf3a30.(CVE-2019-19319)In the Linux kernel
    before version 4.12, Kerberos 5 tickets decoded when
    using the RXRPC keys incorrectly assumes the size of a
    field. This could lead to the size-remaining variable
    wrapping and the data pointer going over the end of the
    buffer. This could possibly lead to memory corruption
    and possible privilege escalation.(CVE-2017-7482)In
    uvc_scan_chain_forward of uvc_driver.c, there is a
    possible linked list corruption due to an unusual root
    cause. This could lead to local escalation of privilege
    in the kernel with no additional execution privileges
    needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-111893654References: Upstream
    kernel(CVE-2020-0404)In various methods of
    hid-multitouch.c, there is a possible out of bounds
    write due to a missing bounds check. This could lead to
    local escalation of privilege with no additional
    execution privileges needed. User interaction is not
    needed for exploitation.Product: AndroidVersions:
    Android kernelAndroid ID: A-162844689References:
    Upstream kernel(CVE-2020-0465)It was found that the raw
    midi kernel driver does not protect against concurrent
    access which leads to a double realloc (double free) in
    snd_rawmidi_input_params() and
    snd_rawmidi_output_status() which are part of
    snd_rawmidi_ioctl() handler in rawmidi.c file. A
    malicious local attacker could possibly use this for
    privilege escalation.(CVE-2018-10902)Linux kernel ext4
    filesystem is vulnerable to an out-of-bound access in
    the ext4_ext_drop_refs() function when operating on a
    crafted ext4 filesystem image.(CVE-2018-10877)Linux
    kernel is vulnerable to a stack-out-of-bounds write in
    the ext4 filesystem code when mounting and writing to a
    crafted ext4 image in ext4_update_inline_data(). An
    attacker could use this to cause a system crash and a
    denial of service.(CVE-2018-10880)Linux Kernel contains
    an out-of-bounds read flaw in the asn1_ber_decoder()
    function in lib/asn1_decoder.c that is triggered when
    decoding ASN.1 data. This may allow a remote attacker
    to disclose potentially sensitive memory
    contents.(CVE-2018-9383)use-after-free read in
    sunkbd_reinit in
    drivers/input/keyboard/sunkbd.c(CVE-2020-25669)mwifiex_
    cmd_802_11_ad_hoc_start in drivers/
    net/wireless/marvell/mwifiex/join.c in the Linux kernel
    through 5.10.4 might allow remote attackers to execute
    arbitrary code via a long SSID value, aka
    CID-5c455c5ab332.(CVE-2020-36158)fs/ nfsd/ nfs3xdr.c in
    the Linux kernel through 5.10.8, when there is an NFS
    export of a subdirectory of a filesystem, allows remote
    attackers to traverse to other parts of the filesystem
    via READDIRPLUS. NOTE: some parties argue that such a
    subdirectory export is not intended to prevent this
    attack see also the exports(5) no_subtree_check default
    behavior.(CVE-2021-3178)In the Linux kernel before
    4.20.8, kvm_ioctl_create_device in virt/kvm/kvm_main.c
    mishandles reference counting because of a race
    condition, leading to a
    use-after-free.(CVE-2019-6974)The KVM implementation in
    the Linux kernel through 4.20.5 has a
    Use-after-Free.(CVE-2019-7221)A flaw was found in the
    JFS filesystem code. This flaw allows a local attacker
    with the ability to set extended attributes to panic
    the system, causing memory corruption or escalating
    privileges. The highest threat from this vulnerability
    is to confidentiality, integrity, as well as system
    availability.(CVE-2020-27815)An out-of-bounds (OOB)
    memory access flaw was found in x25_bind in
    net/x25/af_x25.c in the Linux kernel. A bounds check
    failure allows a local attacker with a user account on
    the system to gain access to out-of-bounds memory,
    leading to a system crash or a leak of internal kernel
    information. The highest threat from this vulnerability
    is to confidentiality, integrity, as well as system
    availability.(CVE-2020-35519)In
    drivers/pci/hotplug/rpadlpar_sysfs.c in the Linux
    kernel through 5.11.8, the RPA PCI Hotplug driver has a
    user-tolerable buffer overflow when writing a new
    device name to the driver from userspace, allowing
    userspace to write data to the kernel stack frame
    directly. This occurs because add_slot_store and
    remove_slot_store mishandle drc_name '\0' termination,
    aka CID-cc7a0bb058b8.(CVE-2021-28972)A NULL pointer
    dereference was found in the net/rds/rdma.c
    __rds_rdma_map() function in the Linux kernel before
    4.14.7 allowing local attackers to cause a system panic
    and a denial-of-service, related to RDS_GET_MR and
    RDS_GET_MR_FOR_DEST.(CVE-2018-7492)The Siemens R3964
    line discipline driver in drivers/tty/ n_r3964.c in the
    Linux kernel before 5.0.8 has multiple race
    conditions.(CVE-2019-11486)The kernel in Android before
    2016-08-05 on Nexus 7 (2013) devices allows attackers
    to gain privileges via a crafted application, aka
    internal bug 28522518.(CVE-2016-3857)The KVM
    implementation in the Linux kernel through 4.14.7
    allows attackers to obtain potentially sensitive
    information from kernel memory, aka a write_mmio
    stack-based out-of-bounds read, related to
    arch/x86/kvm/x86.c and
    include/trace/events/kvm.h.(CVE-2017-17741)The
    sctp_process_param function in net/sctp/sm_make_chunk.c
    in the SCTP implementation in the Linux kernel before
    3.17.4, when ASCONF is used, allows remote attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a malformed INIT
    chunk.(CVE-2014-7841)The XFS subsystem in the Linux
    kernel through 4.8.2 allows local users to cause a
    denial of service (fdatasync failure and system hang)
    by using the vfs syscall group in the trinity program,
    related to a 'page lock order bug in the XFS seek
    hole/data implementation.'(CVE-2016-8660)The
    xfs_dinode_verify function in
    fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel
    through 4.16.3 allows local users to cause a denial of
    service (xfs_ilock_attr_map_shared invalid pointer
    dereference) via a crafted xfs image.(CVE-2018-10322)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1808
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4aedd469");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11815");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
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

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10.h323",
        "kernel-debuginfo-3.10.0-514.44.5.10.h323",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h323",
        "kernel-devel-3.10.0-514.44.5.10.h323",
        "kernel-headers-3.10.0-514.44.5.10.h323",
        "kernel-tools-3.10.0-514.44.5.10.h323",
        "kernel-tools-libs-3.10.0-514.44.5.10.h323",
        "perf-3.10.0-514.44.5.10.h323",
        "python-perf-3.10.0-514.44.5.10.h323"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
