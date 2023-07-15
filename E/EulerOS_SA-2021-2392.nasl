#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153271);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2017-5549",
    "CVE-2017-5897",
    "CVE-2017-7346",
    "CVE-2017-7482",
    "CVE-2017-8069",
    "CVE-2017-8925",
    "CVE-2017-9725",
    "CVE-2017-17741",
    "CVE-2017-18216",
    "CVE-2018-13095",
    "CVE-2018-13406",
    "CVE-2018-14609",
    "CVE-2019-6974",
    "CVE-2020-0404",
    "CVE-2020-0427",
    "CVE-2020-0431",
    "CVE-2020-0433",
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-25669",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
    "CVE-2020-27815",
    "CVE-2020-35519",
    "CVE-2020-36322",
    "CVE-2021-3178",
    "CVE-2021-3347",
    "CVE-2021-3483",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-3609",
    "CVE-2021-20261",
    "CVE-2021-20265",
    "CVE-2021-20292",
    "CVE-2021-23134",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-28964",
    "CVE-2021-28972",
    "CVE-2021-29154",
    "CVE-2021-29265",
    "CVE-2021-30002",
    "CVE-2021-31916",
    "CVE-2021-32078",
    "CVE-2021-32399",
    "CVE-2021-33033"
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2021-2392)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In do_epoll_ctl and ep_loop_check_proc of eventpoll.c,
    there is a possible use after free due to a logic
    error. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for
    exploitation.(CVE-2020-0466)

  - fs/nfsd/nfs3xdr.c in the Linux kernel through 5.10.8,
    when there is an NFS export of a subdirectory of a
    filesystem, allows remote attackers to traverse to
    other parts of the filesystem via READDIRPLUS. NOTE:
    some parties argue that such a subdirectory export is
    not intended to prevent this attack see also the
    exports(5) no_subtree_check default
    behavior.(CVE-2021-3178)

  - An issue was discovered in the Linux kernel through
    5.11.3. A kernel pointer leak can be used to determine
    the address of the iscsi_transport structure. When an
    iSCSI transport is registered with the iSCSI subsystem,
    the transport's handle is available to unprivileged
    users via the sysfs file system, at
    /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When
    read, the show_transport_handle function (in
    drivers/scsi/scsi_transport_iscsi.c) is called, which
    leaks the handle. This handle is actually the pointer
    to an iscsi_transport struct in the kernel module's
    global variables.(CVE-2021-27363)

  - An issue was discovered in the Linux kernel through
    5.11.3. drivers/scsi/scsi_transport_iscsi.c is
    adversely affected by the ability of an unprivileged
    user to craft Netlink messages.(CVE-2021-27364)

  - A race condition was found in the Linux kernels
    implementation of the floppy disk drive controller
    driver software. The impact of this issue is lessened
    by the fact that the default permissions on the floppy
    device (/dev/fd0) are restricted to root. If the
    permissions on the device have changed the impact
    changes greatly. In the default configuration root (or
    equivalent) permissions are required to attack this
    flaw.(CVE-2021-20261)

  - In fs/ocfs2/cluster/nodemanager.c in the Linux kernel
    before 4.15, local users can cause a denial of service
    (NULL pointer dereference and BUG) because a required
    mutex is not used.(CVE-2017-18216)

  - The omninet_open function in
    drivers/usb/serial/omninet.c in the Linux kernel before
    4.10.4 allows local users to cause a denial of service
    (tty exhaustion) by leveraging reference count
    mishandling.(CVE-2017-8925)

  - A flaw was found in the way memory resources were freed
    in the unix_stream_recvmsg function in the Linux kernel
    when a signal was pending. This flaw allows an
    unprivileged local user to crash the system by
    exhausting available memory. The highest threat from
    this vulnerability is to system
    availability.(CVE-2021-20265)

  - A flaw was found in the JFS filesystem code in the
    Linux Kernel which allows a local attacker with the
    ability to set extended attributes to panic the system,
    causing memory corruption or escalating privileges. The
    highest threat from this vulnerability is to
    confidentiality, integrity, as well as system
    availability.(CVE-2020-27815)

  - An out-of-bounds (OOB) memory access flaw was found in
    x25_bind in net/x25/af_x25.c in the Linux kernel
    version v5.12-rc5. A bounds check failure allows a
    local attacker with a user account on the system to
    gain access to out-of-bounds memory, leading to a
    system crash or a leak of internal kernel information.
    The highest threat from this vulnerability is to
    confidentiality, integrity, as well as system
    availability.(CVE-2020-35519)

  - There is a flaw reported in the Linux kernel in
    versions before 5.9 in
    drivers/gpu/drm/nouveau/nouveau_sgdma.c in
    nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The
    issue results from the lack of validating the existence
    of an object prior to performing operations on the
    object. An attacker with a local account with a root
    privilege, can leverage this vulnerability to escalate
    privileges and execute code in the context of the
    kernel.(CVE-2021-20292)

  - In drivers/pci/hotplug/rpadlpar_sysfs.c in the Linux
    kernel through 5.11.8, the RPA PCI Hotplug driver has a
    user-tolerable buffer overflow when writing a new
    device name to the driver from userspace, allowing
    userspace to write data to the kernel stack frame
    directly. This occurs because add_slot_store and
    remove_slot_store mishandle drc_name '\0' termination,
    aka CID-cc7a0bb058b8.(CVE-2021-28972)

  - A race condition was discovered in get_old_root in
    fs/btrfs/ctree.c in the Linux kernel through 5.11.8. It
    allows attackers to cause a denial of service (BUG)
    because of a lack of locking on an extent buffer before
    a cloning operation, aka
    CID-dbcc7d57bffc.(CVE-2021-28964)

  - An issue was discovered in the Linux kernel before
    5.11.7. usbip_sockfd_store in
    drivers/usb/usbip/stub_dev.c allows attackers to cause
    a denial of service (GPF) because the stub-up sequence
    has race conditions during an update of the local and
    shared status, aka CID-9380afd6df70.(CVE-2021-29265)

  - BPF JIT compilers in the Linux kernel through 5.11.12
    have incorrect computation of branch displacements,
    allowing them to execute arbitrary code within the
    kernel context. This affects
    arch/x86/net/bpf_jit_comp.c and
    arch/x86/net/bpf_jit_comp32.c.(CVE-2021-29154)

  - The KVM implementation in the Linux kernel through
    4.14.7 allows attackers to obtain potentially sensitive
    information from kernel memory, aka a write_mmio
    stack-based out-of-bounds read, related to
    arch/x86/kvm/x86.c and
    include/trace/events/kvm.h.(CVE-2017-17741)

  - An issue was discovered in the Linux kernel before
    5.11.3 when a webcam device exists. video_usercopy in
    drivers/media/v4l2-core/v4l2-ioctl.c has a memory leak
    for large arguments, aka
    CID-fb18802a338b.(CVE-2021-30002)

  - An issue was discovered in the Linux kernel through
    4.17.10. There is an invalid pointer dereference in
    __del_reloc_root() in fs/btrfs/relocation.c when
    mounting a crafted btrfs image, related to removing
    reloc rb_trees when reloc control has not been
    initialized.(CVE-2018-14609)

  - An issue was discovered in
    fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel
    through 4.17.3. A denial of service (memory corruption
    and BUG) can occur for a corrupted xfs image upon
    encountering an inode that is in extent format, but has
    more extents than fit in the inode
    fork.(CVE-2018-13095)

  - The vmw_gb_surface_define_ioctl function in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel through 4.10.7 does not validate certain levels
    data, which allows local users to cause a denial of
    service (system hang) via a crafted ioctl call for a
    /dev/dri/renderD* device.(CVE-2017-7346)

  - The klsi_105_get_line_state function in
    drivers/usb/serial/kl5kusb105.c in the Linux kernel
    before 4.9.5 places uninitialized heap-memory contents
    into a log entry upon a failure to read the line
    status, which allows local users to obtain sensitive
    information by reading the log.(CVE-2017-5549)

  - An integer overflow in the uvesafb_setcmap function in
    drivers/video/fbdev/uvesafb.c in the Linux kernel
    before 4.17.4 could result in local attackers being
    able to crash the kernel or potentially elevate
    privileges because kmalloc_array is not
    used.(CVE-2018-13406)

  - In the Linux kernel before version 4.12, Kerberos 5
    tickets decoded when using the RXRPC keys incorrectly
    assumes the size of a field. This could lead to the
    size-remaining variable wrapping and the data pointer
    going over the end of the buffer. This could possibly
    lead to memory corruption and possible privilege
    escalation.(CVE-2017-7482)

  - drivers/net/usb/rtl8150.c in the Linux kernel 4.9.x
    before 4.9.11 interacts incorrectly with the
    CONFIG_VMAP_STACK option, which allows local users to
    cause a denial of service (system crash or memory
    corruption) or possibly have unspecified other impact
    by leveraging use of more than one virtual page for a
    DMA scatterlist.(CVE-2017-8069)

  - An issue was discovered in the Linux kernel through
    5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can
    exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI,
    and has a length up to the maximum length of a Netlink
    message.(CVE-2021-27365)

  - A flaw was found in the Nosy driver in the Linux
    kernel. This issue allows a device to be inserted twice
    into a doubly-linked list, leading to a use-after-free
    when one of these devices is removed. The highest
    threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. Versions
    before kernel 5.12-rc6 are affected(CVE-2021-3483)

  - An issue was discovered in the FUSE filesystem
    implementation in the Linux kernel before 5.10.6, aka
    CID-5d069dbe8aaf. fuse_do_getattr() calls
    make_bad_inode() in inappropriate situations, causing a
    system crash. NOTE: the original fix for this
    vulnerability was incomplete, and its incompleteness is
    tracked as CVE-2021-28950.(CVE-2020-36322)

  - An out-of-bounds (OOB) memory write flaw was found in
    list_devices in drivers/md/dm-ioctl.c in the
    Multi-device driver module in the Linux kernel before
    5.12. A bound check failure allows an attacker with
    special user (CAP_SYS_ADMIN) privilege to gain access
    to out-of-bounds memory leading to a system crash or a
    leak of internal kernel information. The highest threat
    from this vulnerability is to system
    availability.(CVE-2021-31916)

  - A vulnerability was found in Linux Kernel, where a
    refcount leak in llcp_sock_connect() causing
    use-after-free which might lead to privilege
    escalations.(CVE-2020-25671)

  - A vulnerability was found in Linux Kernel where
    refcount leak in llcp_sock_bind() causing
    use-after-free which might lead to privilege
    escalations.(CVE-2020-25670)

  - A memory leak vulnerability was found in Linux kernel
    in llcp_sock_connect(CVE-2020-25672)

  - The Linux kernel before 5.11.14 has a use-after-free in
    cipso_v4_genopt in net/ipv4/cipso_ipv4.c because the
    CIPSO and CALIPSO refcounting for the DOI definitions
    is mishandled, aka CID-ad5d07f4a9cd. This leads to
    writing an arbitrary value.(CVE-2021-33033)

  - Use After Free vulnerability in nfc sockets in the
    Linux Kernel before 5.12.4 allows local attackers to
    elevate their privileges. In typical configurations,
    the issue can only be triggered by a privileged local
    user with the CAP_NET_RAW capability.(CVE-2021-23134)

  - A flaw use-after-free in function
    hci_sock_bound_ioctl() of the Linux kernel HCI
    subsystem was found in the way user detaches bluetooth
    dongle or other way triggers unregister bluetooth
    device event. A local user could use this flaw to crash
    the system or escalate their privileges on the
    system.(CVE-2021-3573)

  - An issue was discovered in the Linux kernel through
    5.10.11. PI futexes have a kernel stack use-after-free
    during fault handling, allowing local users to execute
    code in the kernel, aka
    CID-34b1a1ce1458.(CVE-2021-3347)

  - A vulnerability was found in Linux kernel where
    non-blocking socket in llcp_sock_connect() leads to
    leak and eventually hanging-up the
    system.(CVE-2020-25673)

  - net/bluetooth/hci_request.c in the Linux kernel through
    5.12.2 has a race condition for removal of the HCI
    controller.(CVE-2021-32399)

  - In all Qualcomm products with Android releases from CAF
    using the Linux kernel, during DMA allocation, due to
    wrong data type of size, allocation size gets truncated
    which makes allocation succeed when it should
    fail.(CVE-2017-9725)

  - A flaw double-free memory corruption in the Linux
    kernel HCI device initialization subsystem was found in
    the way user attach malicious HCI TTY Bluetooth device.
    A local user could use this flaw to crash the system.
    This flaw affects all the Linux kernel versions
    starting from 3.13.(CVE-2021-3564)

  - A flaw was found in the CAN BCM networking protocol in
    the Linux kernel, where a local attacker can abuse a
    flaw in the CAN subsystem to corrupt memory, crash the
    system or escalate privileges.(CVE-2021-3609)

  - The ip6gre_err function in net/ipv6/ip6_gre.c in the
    Linux kernel allows remote attackers to have
    unspecified impact via vectors involving GRE flags in
    an IPv6 packet, which trigger an out-of-bounds
    access.(CVE-2017-5897)

  - An Out-of-Bounds Read was discovered in
    arch/arm/mach-footbridge/personal-pci.c in the Linux
    kernel through 5.12.11 because of the lack of a check
    for a value that shouldn't be negative, e.g., access to
    element -2 of an array, aka
    CID-298a58e165e4.(CVE-2021-32078)

  - In the Linux kernel before 4.20.8,
    kvm_ioctl_create_device in virt/kvm/kvm_main.c
    mishandles reference counting because of a race
    condition, leading to a use-after-free.(CVE-2019-6974)

  - In uvc_scan_chain_forward of uvc_driver.c, there is a
    possible linked list corruption due to an unusual root
    cause. This could lead to local escalation of privilege
    in the kernel with no additional execution privileges
    needed. User interaction is not needed for
    exploitation.(CVE-2020-0404)

  - In create_pinctrl of core.c, there is a possible out of
    bounds read due to a use after free. This could lead to
    local information disclosure with no additional
    execution privileges needed. User interaction is not
    needed for exploitation.(CVE-2020-0427)

  - In kbd_keycode of keyboard.c, there is a possible out
    of bounds write due to a missing bounds check. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-144161459(CVE-2020-0431)

  - In blk_mq_queue_tag_busy_iter of blk-mq-tag.c, there is
    a possible use after free due to improper locking. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User
    interaction is not needed for
    exploitation.(CVE-2020-0433)

  - In various methods of hid-multitouch.c, there is a
    possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for
    exploitation.(CVE-2020-0465)

  - A vulnerability was found in the Linux Kernel where the
    function sunkbd_reinit having been scheduled by
    sunkbd_interrupt before sunkbd being freed. Though the
    dangling pointer is set to NULL in sunkbd_disconnect,
    there is still an alias in sunkbd_reinit causing Use
    After Free.(CVE-2020-25669)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2392
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbdb8385");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9725");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-5897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

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

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["kernel-3.10.0-327.62.59.83.h281",
        "kernel-debug-3.10.0-327.62.59.83.h281",
        "kernel-debug-devel-3.10.0-327.62.59.83.h281",
        "kernel-debuginfo-3.10.0-327.62.59.83.h281",
        "kernel-debuginfo-common-x86_64-3.10.0-327.62.59.83.h281",
        "kernel-devel-3.10.0-327.62.59.83.h281",
        "kernel-headers-3.10.0-327.62.59.83.h281",
        "kernel-tools-3.10.0-327.62.59.83.h281",
        "kernel-tools-libs-3.10.0-327.62.59.83.h281",
        "perf-3.10.0-327.62.59.83.h281",
        "python-perf-3.10.0-327.62.59.83.h281"];

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
