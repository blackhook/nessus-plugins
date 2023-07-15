#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148041);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-9517",
    "CVE-2019-3900",
    "CVE-2019-19338",
    "CVE-2019-20934",
    "CVE-2020-0543",
    "CVE-2020-4788",
    "CVE-2020-10690",
    "CVE-2020-12351",
    "CVE-2020-14305",
    "CVE-2020-15436",
    "CVE-2020-15437",
    "CVE-2020-25669",
    "CVE-2020-25704",
    "CVE-2020-27777",
    "CVE-2020-27786",
    "CVE-2020-28915",
    "CVE-2020-28974",
    "CVE-2020-29370",
    "CVE-2020-29371",
    "CVE-2020-29660",
    "CVE-2020-29661",
    "CVE-2020-36158"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2021-1684)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - mwifiex_cmd_802_11_ad_hoc_start in
    drivers/net/wireless/marvell/mwifiex/join.c in the
    Linux kernel through 5.10.4 might allow remote
    attackers to execute arbitrary code via a long SSID
    value, aka CID-5c455c5ab332.(CVE-2020-36158)

  - Incomplete cleanup from specific special register read
    operations in some Intel(R) Processors may allow an
    authenticated user to potentially enable information
    disclosure via local access.(CVE-2020-0543)

  - An infinite loop issue was found in the vhost_net
    kernel module in Linux Kernel up to and including
    v5.1-rc6, while handling incoming packets in
    handle_rx(). It could occur if one end sends packets
    faster than the other end can process them. A guest
    user, maybe remote one, could use this flaw to stall
    the vhost_net kernel thread, resulting in a DoS
    scenario.(CVE-2019-3900)

  - In pppol2tp_connect, there is possible memory
    corruption due to a use after free. This could lead to
    local escalation of privilege with System execution
    privileges needed. User interaction is not needed for
    exploitation. Product: Android. Versions: Android
    kernel. Android ID: A-38159931.(CVE-2018-9517)

  - A flaw was found in the fix for CVE-2019-11135, in the
    Linux upstream kernel versions before 5.5 where, the
    way Intel CPUs handle speculative execution of
    instructions when a TSX Asynchronous Abort (TAA) error
    occurs. When a guest is running on a host CPU affected
    by the TAA flaw (TAA_NO=0), but is not affected by the
    MDS issue (MDS_NO=1), the guest was to clear the
    affected buffers by using a VERW instruction mechanism.
    But when the MDS_NO=1 bit was exported to the guests,
    the guests did not use the VERW mechanism to clear the
    affected buffers. This issue affects guests running on
    Cascade Lake CPUs and requires that host has 'TSX'
    enabled. Confidentiality of data is the highest threat
    associated with this vulnerability.(CVE-2019-19338)

  - There is a use-after-free in kernel versions before 5.5
    due to a race condition between the release of
    ptp_clock and cdev while resource deallocation. When a
    (high privileged) process allocates a ptp device file
    (like /dev/ptpX) and voluntarily goes to sleep. During
    this time if the underlying device is removed, it can
    cause an exploitable condition as the process wakes up
    to terminate and clean all attached files. The system
    crashes due to the cdev structure being invalid (as
    already freed) which is pointed to by the
    inode.(CVE-2020-10690)

  - Improper input validation in BlueZ may allow an
    unauthenticated user to potentially enable escalation
    of privilege via adjacent access.(CVE-2020-12351)

  - A flaw was found in the Linux kernels implementation of
    MIDI, where an attacker with a local account and the
    permissions to issue an ioctl commands to midi devices,
    could trigger a use-after-free. A write to this
    specific memory while freed and before use could cause
    the flow of execution to change and possibly allow for
    memory corruption or privilege
    escalation.(CVE-2020-27786)

  - use-after-free read in sunkbd_reinit in
    drivers/input/keyboard/sunkbd.c(CVE-2020-25669)

  - A flaw was found in the way RTAS handled memory
    accesses in userspace to kernel communication. On a
    locked down (usually due to Secure Boot) guest system
    running on top of PowerVM or KVM hypervisors (pseries
    platform) a root like local user could use this flaw to
    further increase their privileges to that of a running
    kernel.(CVE-2020-27777)

  - A locking inconsistency issue was discovered in the tty
    subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may
    allow a read-after-free attack against TIOCGSID, aka
    CID-c8bcd9c5be24.(CVE-2020-29660)

  - A locking issue was discovered in the tty subsystem of
    the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free
    attack against TIOCSPGRP, aka
    CID-54ffccbf053b.(CVE-2020-29661)

  - An out-of-bounds memory write flaw was found in how the
    Linux kernel's Voice Over IP H.323 connection tracking
    functionality handled connections on ipv6 port 1720.
    This flaw allows an unauthenticated remote user to
    crash the system, causing a denial of service. The
    highest threat from this vulnerability is to
    confidentiality, integrity, as well as system
    availability.(CVE-2020-14305)

  - An issue was discovered in the Linux kernel before
    5.2.6. On NUMA systems, the Linux fair scheduler has a
    use-after-free in show_numa_stats() because NUMA fault
    statistics are inappropriately freed, aka
    CID-16d51a590a8c.(CVE-2019-20934)

  - IBM Power9 (AIX 7.1, 7.2, and VIOS 3.1) processors
    could allow a local user to obtain sensitive
    information from the data in the L1 cache under
    extenuating circumstances. IBM X-Force ID:
    189296.(CVE-2020-4788)

  - A flaw memory leak in the Linux kernel performance
    monitoring subsystem was found in the way if using
    PERF_EVENT_IOC_SET_FILTER. A local user could use this
    flaw to starve the resources causing denial of
    service.(CVE-2020-25704)

  - An issue was discovered in kmem_cache_alloc_bulk in
    mm/slub.c in the Linux kernel before 5.5.11. The
    slowpath lacks the required TID increment, aka
    CID-fd4d9c7d0c71.(CVE-2020-29370)

  - A slab-out-of-bounds read in fbcon in the Linux kernel
    before 5.9.7 could be used by local attackers to read
    privileged information or potentially crash the kernel,
    aka CID-3c4e0dff2095. This occurs because
    KD_FONT_OP_COPY in drivers/tty/vt/vt.c can be used for
    manipulations such as font height.(CVE-2020-28974)

  - A buffer over-read (at the framebuffer layer) in the
    fbcon code in the Linux kernel before 5.8.15 could be
    used by local attackers to read kernel memory, aka
    CID-6735b4632def.(CVE-2020-28915)

  - An issue was discovered in romfs_dev_read in
    fs/romfs/storage.c in the Linux kernel before 5.8.4.
    Uninitialized memory leaks to userspace, aka
    CID-bcf85fcedfdd.(CVE-2020-29371)

  - Use-after-free vulnerability in fs/block_dev.c in the
    Linux kernel before 5.8 allows local users to gain
    privileges or cause a denial of service by leveraging
    improper access to a certain error
    field.(CVE-2020-15436)

  - The Linux kernel before version 5.8 is vulnerable to a
    NULL pointer dereference in
    drivers/tty/serial/8250/8250_core.c:serial8250_isa_init
    _ports() that allows local users to cause a denial of
    service by using the p->serial_in pointer which
    uninitialized.(CVE-2020-15437)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1684
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a74b185");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.5.h520.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.5.h520.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.5.h520.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.5.h520.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.5.h520.eulerosv2r7",
        "perf-3.10.0-862.14.1.5.h520.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.5.h520.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
