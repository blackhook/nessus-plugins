#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151229);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2019-14615",
    "CVE-2019-16230",
    "CVE-2019-19377",
    "CVE-2019-19813",
    "CVE-2019-20810",
    "CVE-2020-0431",
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-7053",
    "CVE-2020-8648",
    "CVE-2020-10757",
    "CVE-2020-10773",
    "CVE-2020-10781",
    "CVE-2020-11494",
    "CVE-2020-12114",
    "CVE-2020-12351",
    "CVE-2020-12656",
    "CVE-2020-14305",
    "CVE-2020-15436",
    "CVE-2020-15437",
    "CVE-2020-25656",
    "CVE-2020-25669",
    "CVE-2020-25704",
    "CVE-2020-27777",
    "CVE-2020-27786",
    "CVE-2020-27815",
    "CVE-2020-28915",
    "CVE-2020-28974",
    "CVE-2020-29370",
    "CVE-2020-29371",
    "CVE-2020-35519",
    "CVE-2020-36158",
    "CVE-2021-3178",
    "CVE-2021-3428",
    "CVE-2021-3483",
    "CVE-2021-20292",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-28964",
    "CVE-2021-28972",
    "CVE-2021-29154",
    "CVE-2021-29265",
    "CVE-2021-30002"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.6 : kernel (EulerOS-SA-2021-2040)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - Use-after-free vulnerability in fs/block_dev.c in the
    Linux kernel before 5.8 allows local users to gain
    privileges or cause a denial of service by leveraging
    improper access to a certain error
    field.(CVE-2020-15436)

  - An out-of-bounds memory write flaw was found in how the
    Linux kernel's Voice Over IP H.323 connection tracking
    functionality handled connections on ipv6 port 1720.
    This flaw allows an unauthenticated remote user to
    crash the system, causing a denial of service. The
    highest threat from this vulnerability is to
    confidentiality, integrity, as well as system
    availability.(CVE-2020-14305)

  - Improper input validation in BlueZ may allow an
    unauthenticated user to potentially enable escalation
    of privilege via adjacent access.(CVE-2020-12351)

  - In the Linux kernel 4.14 longterm through 4.14.165 and
    4.19 longterm through 4.19.96 (and 5.x before 5.2),
    there is a use-after-free (write) in the
    i915_ppgtt_close function in
    drivers/gpu/drm/i915/i915_gem_gtt.c, aka
    CID-7dc40713618c. This is related to
    i915_gem_context_destroy_ioctl in
    drivers/gpu/drm/i915/i915_gem_context.c.(CVE-2020-7053)

  - In kbd_keycode of keyboard.c, there is a possible out
    of bounds write due to a missing bounds check. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-144161459(CVE-2020-0431)

  - In various methods of hid-multitouch.c, there is a
    possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-162844689References: Upstream kernel(CVE-2020-0465)

  - mwifiex_cmd_802_11_ad_hoc_start in
    drivers/net/wireless/marvell/mwifiex/join.c in the
    Linux kernel through 5.10.4 might allow remote
    attackers to execute arbitrary code via a long SSID
    value, aka CID-5c455c5ab332.(CVE-2020-36158)

  - A flaw was found in the way RTAS handled memory
    accesses in userspace to kernel communication. On a
    locked down (usually due to Secure Boot) guest system
    running on top of PowerVM or KVM hypervisors (pseries
    platform) a root like local user could use this flaw to
    further increase their privileges to that of a running
    kernel.(CVE-2020-27777)

  - An issue was discovered in romfs_dev_read in
    fs/romfs/storage.c in the Linux kernel before 5.8.4.
    Uninitialized memory leaks to userspace, aka
    CID-bcf85fcedfdd.(CVE-2020-29371)

  - An issue was discovered in kmem_cache_alloc_bulk in
    mm/slub.c in the Linux kernel before 5.5.11. The
    slowpath lacks the required TID increment, aka
    CID-fd4d9c7d0c71.(CVE-2020-29370)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the n_tty_receive_buf_common
    function in drivers/tty/n_tty.c.(CVE-2020-8648)

  - A buffer over-read (at the framebuffer layer) in the
    fbcon code in the Linux kernel before 5.8.15 could be
    used by local attackers to read kernel memory, aka
    CID-6735b4632def.(CVE-2020-28915)

  - In the Linux kernel 5.0.21, mounting a crafted btrfs
    filesystem image, performing some operations, and then
    making a syncfs system call can lead to a
    use-after-free in __mutex_lock in
    kernel/locking/mutex.c. This is related to
    mutex_can_spin_on_owner in kernel/locking/mutex.c,
    __btrfs_qgroup_free_meta in fs/btrfs/qgroup.c, and
    btrfs_insert_delayed_items in
    fs/btrfs/delayed-inode.c.(CVE-2019-19813)

  - gss_mech_free in net/sunrpc/auth_gss/gss_mech_switch.c
    in the rpcsec_gss_krb5 implementation in the Linux
    kernel through 5.6.10 lacks certain domain_release
    calls, leading to a memory leak.(CVE-2020-12656)

  - A flaw was found in the Linux kernels implementation of
    MIDI, where an attacker with a local account and the
    permissions to issue an ioctl commands to midi devices,
    could trigger a use-after-free. A write to this
    specific memory while freed and before use could cause
    the flow of execution to change and possibly allow for
    memory corruption or privilege
    escalation.(CVE-2020-27786)

  - A flaw memory leak in the Linux kernel performance
    monitoring subsystem was found in the way if using
    PERF_EVENT_IOC_SET_FILTER. A local user could use this
    flaw to starve the resources causing denial of
    service.(CVE-2020-25704)

  - A flaw was found in the Linux Kernel before 5.8-rc6 in
    the ZRAM kernel module, where a user with a local
    account and the ability to read the
    /sys/class/zram-control/hot_add file can create ZRAM
    device nodes in the /dev/ directory. This read
    allocates kernel memory and is not accounted for a user
    that triggers the creation of that ZRAM device. With
    this vulnerability, continually reading the device may
    consume a large amount of system memory and cause the
    Out-of-Memory (OOM) killer to activate and terminate
    random userspace processes, possibly making the system
    inoperable.(CVE-2020-10781)

  - go7007_snd_init in
    drivers/media/usb/go7007/snd-go7007.c in the Linux
    kernel before 5.6 does not call snd_card_free for a
    failure path, which causes a memory leak, aka
    CID-9453264ef586.(CVE-2019-20810)

  - An issue was discovered in the Linux kernel through
    5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can
    exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI,
    and has a length up to the maximum length of a Netlink
    message.(CVE-2021-27365)

  - An issue was discovered in the Linux kernel through
    5.11.3. drivers/scsi/scsi_transport_iscsi.c is
    adversely affected by the ability of an unprivileged
    user to craft Netlink messages.(CVE-2021-27364)

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

  - A vulnerability was found in the Linux Kernel where the
    function sunkbd_reinit having been scheduled by
    sunkbd_interrupt before sunkbd being freed. Though the
    dangling pointer is set to NULL in sunkbd_disconnect,
    there is still an alias in sunkbd_reinit causing Use
    After Free.(CVE-2020-25669)

  - A flaw was found in the Linux kernel. A use-after-free
    was found in the way the console subsystem was using
    ioctls KDGKBSENT and KDSKBSENT. A local user could use
    this flaw to get read memory access out of bounds. The
    highest threat from this vulnerability is to data
    confidentiality.(CVE-2020-25656)

  - The Linux kernel before version 5.8 is vulnerable to a
    NULL pointer dereference in
    drivers/tty/serial/8250/8250_core.c:serial8250_isa_init
    _ports() that allows local users to cause a denial of
    service by using the p->serial_in pointer which
    uninitialized.(CVE-2020-15437)

  - An issue was discovered in slc_bump in
    drivers/net/can/slcan.c in the Linux kernel through
    5.6.2. It allows attackers to read uninitialized
    can_frame data, potentially containing sensitive
    information from kernel stack memory, if the
    configuration lacks CONFIG_INIT_STACK_ALL, aka
    CID-b9258a2cece4.(CVE-2020-11494)

  - A stack information leak flaw was found in s390/s390x
    in the Linux kernel's memory manager functionality,
    where it incorrectly writes to the
    /proc/sys/vm/cmm_timeout file. This flaw allows a local
    user to see the kernel data.(CVE-2020-10773)

  - ** DISPUTED ** drivers/gpu/drm/radeon/radeon_display.c
    in the Linux kernel 5.2.14 does not check the
    alloc_workqueue return value, leading to a NULL pointer
    dereference. NOTE: A third-party software maintainer
    states that the work queue allocation is happening
    during device initialization, which for a graphics card
    occurs during boot. It is not attacker controllable and
    OOM at that time is highly unlikely.(CVE-2019-16230)

  - A flaw was found in the Linux Kernel in versions after
    4.5-rc1 in the way mremap handled DAX Huge Pages. This
    flaw allows a local attacker with access to a DAX
    enabled storage to escalate their privileges on the
    system.(CVE-2020-10757)

  - A pivot_root race condition in fs/namespace.c in the
    Linux kernel 4.4.x before 4.4.221, 4.9.x before
    4.9.221, 4.14.x before 4.14.178, 4.19.x before
    4.19.119, and 5.x before 5.3 allows local users to
    cause a denial of service (panic) by corrupting a
    mountpoint reference counter.(CVE-2020-12114)

  - A slab-out-of-bounds read in fbcon in the Linux kernel
    before 5.9.7 could be used by local attackers to read
    privileged information or potentially crash the kernel,
    aka CID-3c4e0dff2095. This occurs because
    KD_FONT_OP_COPY in drivers/tty/vt/vt.c can be used for
    manipulations such as font height.(CVE-2020-28974)

  - Insufficient control flow in certain data structures
    for some Intel(R) Processors with Intel(R) Processor
    Graphics may allow an unauthenticated user to
    potentially enable information disclosure via local
    access.(CVE-2019-14615)

  - In the Linux kernel 5.0.21, mounting a crafted btrfs
    filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in
    btrfs_queue_work in
    fs/btrfs/async-thread.c.(CVE-2019-19377)

  - In do_epoll_ctl and ep_loop_check_proc of eventpoll.c,
    there is a possible use after free due to a logic
    error. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-147802478References: Upstream kernel(CVE-2020-0466)

  - ** DISPUTED ** fs/nfsd/nfs3xdr.c in the Linux kernel
    through 5.10.8, when there is an NFS export of a
    subdirectory of a filesystem, allows remote attackers
    to traverse to other parts of the filesystem via
    READDIRPLUS. NOTE: some parties argue that such a
    subdirectory export is not intended to prevent this
    attack see also the exports(5) no_subtree_check default
    behavior.(CVE-2021-3178)

  - A flaw was found in the Linux kernels eBPF
    implementation. By default, accessing the eBPF verifier
    is only accessible to privileged users with
    CAP_SYS_ADMIN. A local user with the ability to insert
    eBPF instructions can abuse a flaw in eBPF to corrupt
    memory. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system
    availability.(CVE-2021-29154)

  - A flaw memory leak in the Linux kernel webcam device
    functionality was found in the way user calls ioctl
    that triggers video_usercopy function. The highest
    threat from this vulnerability is to system
    availability.(CVE-2021-30002)

  - A flaw was found in the Nosy driver in the Linux
    kernel. This issue allows a device to be inserted twice
    into a doubly-linked list, leading to a use-after-free
    when one of these devices is removed. The highest
    threat from this vulnerability is to confidentiality,
    integrity, as well as system
    availability.(CVE-2021-3483)

  - A flaw in the Linux kernels implementation of the RPA
    PCI Hotplug driver for power-pc. A user with
    permissions to write to the sysfs settings for this
    driver can trigger a buffer overflow when writing a new
    device name to the driver from userspace, overwriting
    data in the kernel's stack.(CVE-2021-28972)

  - A race condition flaw was found in get_old_root in
    fs/btrfs/ctree.c in the Linux kernel in btrfs
    file-system. This flaw allows a local attacker with a
    special user privilege to cause a denial of service due
    to not locking an extent buffer before a cloning
    operation. The highest threat from this vulnerability
    is to system availability.(CVE-2021-28964)

  - A flaw was found in the Linux kernel. The usbip driver
    allows attackers to cause a denial of service (GPF)
    because the stub-up sequence has race conditions during
    an update of the local and shared status. The highest
    threat from this vulnerability is to system
    availability.(CVE-2021-29265)

  - An out-of-bounds (OOB) memory access flaw was found in
    x25_bind in net/x25/af_x25.c in the Linux kernel. A
    bounds check failure allows a local attacker with a
    user account on the system to gain access to
    out-of-bounds memory, leading to a system crash or a
    leak of internal kernel information. The highest threat
    from this vulnerability is to confidentiality,
    integrity, as well as system
    availability.(CVE-2020-35519)

  - There is a flaw reported in
    drivers/gpu/drm/nouveau/nouveau_sgdma.c in
    nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The
    issue results from the lack of validating the existence
    of an object prior to performing operations on the
    object. An attacker with a local account with a root
    privilege, can leverage this vulnerability to escalate
    privileges and execute code in the context of the
    kernel.(CVE-2021-20292)

  - A flaw was found in the JFS filesystem code. This flaw
    allows a local attacker with the ability to set
    extended attributes to panic the system, causing memory
    corruption or escalating privileges. The highest threat
    from this vulnerability is to confidentiality,
    integrity, as well as system
    availability.(CVE-2020-27815)

  - A flaw was found in the Linux kernel. A denial of
    service problem is identified if an extent tree is
    corrupted in a crafted ext4 filesystem in
    fs/ext4/extents.c in ext4_es_cache_extent. Fabricating
    an integer overflow, A local attacker with a special
    user privilege may cause a system crash problem which
    can lead to an availability threat.(CVE-2021-3428)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2040
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efda5723");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14305");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_137",
        "kernel-devel-3.10.0-862.14.1.6_137",
        "kernel-headers-3.10.0-862.14.1.6_137",
        "kernel-tools-3.10.0-862.14.1.6_137",
        "kernel-tools-libs-3.10.0-862.14.1.6_137",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_137",
        "perf-3.10.0-862.14.1.6_137",
        "python-perf-3.10.0-862.14.1.6_137"];

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
