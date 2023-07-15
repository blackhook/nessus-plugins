#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124973);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2013-7269",
    "CVE-2014-2309",
    "CVE-2014-3647",
    "CVE-2014-7826",
    "CVE-2015-2922",
    "CVE-2015-4036",
    "CVE-2015-7550",
    "CVE-2016-3136",
    "CVE-2016-4482",
    "CVE-2016-4485",
    "CVE-2016-8630",
    "CVE-2016-8646",
    "CVE-2017-18221",
    "CVE-2017-18261",
    "CVE-2017-7294",
    "CVE-2018-10881",
    "CVE-2018-1120",
    "CVE-2018-13099",
    "CVE-2018-14612",
    "CVE-2018-20784"
  );
  script_bugtraq_id(
    64742,
    66095,
    70748,
    70971,
    74315,
    74664
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1520)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - Array index error in the tcm_vhost_make_tpg function in
    drivers/vhost/scsi.c in the Linux kernel before 4.0
    might allow guest OS users to cause a denial of service
    (memory corruption) or possibly have unspecified other
    impact via a crafted VHOST_SCSI_SET_ENDPOINT ioctl
    call. NOTE: the affected function was renamed to
    vhost_scsi_make_tpg before the vulnerability was
    announced.(CVE-2015-4036i1/4%0

  - The llc_cmsg_rcv function in net/llc/af_llc.c in the
    Linux kernel before 4.5.5 does not initialize a certain
    data structure, which allows attackers to obtain
    sensitive information from kernel stack memory by
    reading a message.(CVE-2016-4485i1/4%0

  - The nr_recvmsg function in net/netrom/af_netrom.c in
    the Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7269i1/4%0

  - The mct_u232_msr_to_state function in
    drivers/usb/serial/mct_u232.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted USB device without two
    interrupt-in endpoint descriptors.(CVE-2016-3136i1/4%0

  - An out-of-bounds memory access flaw, CVE-2014-7825, was
    found in the syscall tracing functionality of the Linux
    kernel's perf subsystem. A local, unprivileged user
    could use this flaw to crash the system. Additionally,
    an out-of-bounds memory access flaw, CVE-2014-7826, was
    found in the syscall tracing functionality of the Linux
    kernel's ftrace subsystem. On a system with ftrace
    syscall tracing enabled, a local, unprivileged user
    could use this flaw to crash the system, or escalate
    their privileges.(CVE-2014-7826i1/4%0

  - Linux kernel built with the Kernel-based Virtual
    Machine (CONFIG_KVM) support is vulnerable to a null
    pointer dereference flaw. It could occur on x86
    platform, when emulating an undefined instruction. An
    attacker could use this flaw to crash the host kernel
    resulting in DoS.(CVE-2016-8630i1/4%0

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bound access in
    ext4_get_group_info function, a denial of service, and
    a system crash by mounting and operating on a crafted
    ext4 filesystem image.(CVE-2018-10881i1/4%0

  - The arch_timer_reg_read_stable macro in
    arch/arm64/include/asm/arch_timer.h in the Linux kernel
    before 4.13 allows local users to cause a denial of
    service (infinite recursion) by writing to a file under
    /sys/kernel/debug in certain circumstances, as
    demonstrated by a scenario involving debugfs, ftrace,
    PREEMPT_TRACER, and
    FUNCTION_GRAPH_TRACER.(CVE-2017-18261i1/4%0

  - The ip6_route_add function in net/ipv6/route.c in the
    Linux kernel through 3.13.6 does not properly count the
    addition of routes, which allows remote attackers to
    cause a denial of service (memory consumption) via a
    flood of ICMPv6 Router Advertisement
    packets.(CVE-2014-2309i1/4%0

  - In the Linux kernel before 4.20.2, kernel/sched/fair.c
    mishandles leaf cfs_rq's, which allows attackers to
    cause a denial of service (infinite loop in
    update_blocked_averages) or possibly have unspecified
    other impact by inducing a high load.(CVE-2018-20784i1/4%0

  - An issue was discovered in the F2FS filesystem code in
    fs/f2fs/inline.c in the Linux kernel. A denial of
    service due to the out-of-bounds memory access can
    occur for a modified f2fs filesystem
    image.(CVE-2018-13099i1/4%0

  - An out-of-bounds write vulnerability was found in the
    Linux kernel's vmw_surface_define_ioctl() function, in
    the 'drivers/gpu/drm/vmwgfx/vmwgfx_surface.c' file. Due
    to the nature of the flaw, privilege escalation cannot
    be fully ruled out, although we believe it is
    unlikely.(CVE-2017-7294i1/4%0

  - A flaw was found in the way the Linux kernel's KVM
    subsystem handled non-canonical addresses when
    emulating instructions that change the RIP (for
    example, branches or calls). A guest user with access
    to an I/O or MMIO region could use this flaw to crash
    the guest.(CVE-2014-3647i1/4%0

  - The __munlock_pagevec function in mm/mlock.c in the
    Linux kernel, before 4.11.4, allows local users to
    cause a denial of service (NR_MLOCK accounting
    corruption) via crafted use of mlockall and munlockall
    system calls.(CVE-2017-18221i1/4%0

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2018-1120i1/4%0

  - The proc_connectinfo() function in
    'drivers/usb/core/devio.c' in the Linux kernel through
    4.6 does not initialize a certain data structure, which
    allows local users to obtain sensitive information from
    kernel stack memory via a crafted USBDEVFS_CONNECTINFO
    ioctl call. The stack object 'ci' has a total size of 8
    bytes. Its last 3 bytes are padding bytes which are not
    initialized and are leaked to
    userland.(CVE-2016-4482i1/4%0

  - A vulnerability was found in the Linux kernel. An
    unprivileged local user could trigger oops in
    shash_async_export() by attempting to force the
    in-kernel hashing algorithms into decrypting an empty
    data set.(CVE-2016-8646i1/4%0

  - An issue was discovered in the btrfs filesystem code in
    the Linux kernel. An invalid NULL pointer dereference
    in btrfs_root_node() when mounting a crafted btrfs
    image is due to a lack of chunk block group mapping
    validation in btrfs_read_block_groups() in the
    fs/btrfs/extent-tree.c function and a lack of
    empty-tree checks in check_leaf() in
    fs/btrfs/tree-checker.c function. This could lead to a
    system crash and a denial of service.(CVE-2018-14612i1/4%0

  - It was found that the Linux kernel's TCP/IP protocol
    suite implementation for IPv6 allowed the Hop Limit
    value to be set to a smaller value than the default
    one. An attacker on a local network could use this flaw
    to prevent systems on that network from sending or
    receiving network packets.(CVE-2015-2922i1/4%0

  - A NULL-pointer dereference flaw was found in the
    kernel, which is caused by a race between revoking a
    user-type key and reading from it. The issue could be
    triggered by an unprivileged user with a local account,
    causing the kernel to crash (denial of
    service).(CVE-2015-7550i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1520
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f904a7a8");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.28-1.2.117",
        "kernel-devel-4.19.28-1.2.117",
        "kernel-headers-4.19.28-1.2.117",
        "kernel-tools-4.19.28-1.2.117",
        "kernel-tools-libs-4.19.28-1.2.117",
        "kernel-tools-libs-devel-4.19.28-1.2.117",
        "perf-4.19.28-1.2.117",
        "python-perf-4.19.28-1.2.117"];

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
