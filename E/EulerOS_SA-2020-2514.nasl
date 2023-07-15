#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144168);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-20934",
    "CVE-2020-0431",
    "CVE-2020-4788",
    "CVE-2020-8694",
    "CVE-2020-10690",
    "CVE-2020-25656",
    "CVE-2020-25668",
    "CVE-2020-25669",
    "CVE-2020-25704",
    "CVE-2020-25705",
    "CVE-2020-27673",
    "CVE-2020-27675",
    "CVE-2020-27777",
    "CVE-2020-28915",
    "CVE-2020-28974",
    "CVE-2020-29368",
    "CVE-2020-29370",
    "CVE-2020-29371"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2020-2514)");

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
    output, etc.Security Fix(es):An issue was discovered in
    __split_huge_pmd in mm/huge_memory.c in the Linux
    kernel before 5.7.5. The copy-on-write implementation
    can grant unintended write access because of a race
    condition in a THP mapcount check, aka
    CID-c444eb564fb1.(CVE-2020-29368)An issue was
    discovered in kmem_cache_alloc_bulk in mm/slub.c in the
    Linux kernel before 5.5.11. The slowpath lacks the
    required TID increment, aka
    CID-fd4d9c7d0c71.(CVE-2020-29370)An issue was
    discovered in romfs_dev_read in fs/romfs/storage.c in
    the Linux kernel before 5.8.4. Uninitialized memory
    leaks to userspace, aka
    CID-bcf85fcedfdd.(CVE-2020-29371)An issue was
    discovered in the Linux kernel before 5.2.6. On NUMA
    systems, the Linux fair scheduler has a use-after-free
    in show_numa_stats() because NUMA fault statistics are
    inappropriately freed, aka
    CID-16d51a590a8c.(CVE-2019-20934)kernel:use-after-free
    read in sunkbd_reinit in
    drivers/input/keyboard/sunkbd.c(CVE-2020-25669)A buffer
    over-read (at the framebuffer layer) in the fbcon code
    in the Linux kernel before 5.8.15 could be used by
    local attackers to read kernel memory, aka
    CID-6735b4632def.(CVE-2020-28915)IBM Power9 (AIX 7.1,
    7.2, and VIOS 3.1) processors could allow a local user
    to obtain sensitive information from the data in the L1
    cache under extenuating circumstances. IBM X-Force ID:
    189296.(CVE-2020-4788)kernel: powerpc: RTAS calls can
    be used to compromise kernel
    integrity(CVE-2020-27777)There is a use-after-free in
    kernel versions before 5.5 due to a race condition
    between the release of ptp_clock and cdev while
    resource deallocation. When a (high privileged) process
    allocates a ptp device file (like /dev/ptpX) and
    voluntarily goes to sleep. During this time if the
    underlying device is removed, it can cause an
    exploitable condition as the process wakes up to
    terminate and clean all attached files. The system
    crashes due to the cdev structure being invalid (as
    already freed) which is pointed to by the
    inode.(CVE-2020-10690)An issue was discovered in the
    Linux kernel through 5.9.1, as used with Xen through
    4.14.x. Guest OS users can cause a denial of service
    (host OS hang) via a high rate of events to dom0, aka
    CID-e99502f76271.(CVE-2020-27673)An issue was
    discovered in the Linux kernel through 5.9.1, as used
    with Xen through 4.14.x.
    drivers/xen/events/events_base.c allows event-channel
    removal during the event-handling loop (a race
    condition). This can cause a use-after-free or NULL
    pointer dereference, as demonstrated by a dom0 crash
    via events for an in-reconfiguration paravirtualized
    device, aka CID-073d0552ead5.(CVE-2020-27675)A flaw
    memory leak in the Linux kernel performance monitoring
    subsystem was found in the way if using
    PERF_EVENT_IOC_SET_FILTER. A local user could use this
    flaw to starve the resources causing denial of
    service.(CVE-2020-25704)Insufficient access control in
    the Linux kernel driver for some Intel(R) Processors
    may allow an authenticated user to potentially enable
    information disclosure via local
    access.(CVE-2020-8694)kernel: race condition in
    fg_console can lead to use-after-free in
    con_font_op(CVE-2020-25668)A flaw in the way reply ICMP
    packets are limited in the Linux kernel functionality
    was found that allows to quickly scan open UDP ports.
    This flaw allows an off-path remote user to effectively
    bypassing source port UDP randomization. The highest
    threat from this vulnerability is to confidentiality
    and possibly integrity, because software that relies on
    UDP source port randomization are indirectly affected
    as well. Kernel versions before 5.10 may be vulnerable
    to this issue.(CVE-2020-25705)A slab-out-of-bounds read
    in fbcon in the Linux kernel before 5.9.7 could be used
    by local attackers to read privileged information or
    potentially crash the kernel, aka CID-3c4e0dff2095.
    This occurs because KD_FONT_OP_COPY in
    drivers/tty/vt/vt.c can be used for manipulations such
    as font height.(CVE-2020-28974)A flaw was found in the
    Linux kernel. A use-after-free was found in the way the
    console subsystem was using ioctls KDGKBSENT and
    KDSKBSENT. A local user could use this flaw to get read
    memory access out of bounds. The highest threat from
    this vulnerability is to data
    confidentiality.(CVE-2020-25656)In kbd_keycode of
    keyboard.c, there is a possible out of bounds write due
    to a missing bounds check. This could lead to local
    escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-144161459(CVE-2020-0431)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2514
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc260590");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27777");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25669");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h906.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h906.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h906.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h906.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h906.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h906.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h906.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h906.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h906.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h906.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
