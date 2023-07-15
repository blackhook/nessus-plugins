#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119921);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id(
    "CVE-2018-1092",
    "CVE-2018-5803",
    "CVE-2018-5848",
    "CVE-2018-10878",
    "CVE-2018-10881",
    "CVE-2018-14633",
    "CVE-2018-15594",
    "CVE-2018-16276",
    "CVE-2018-16658",
    "CVE-2018-18386",
    "CVE-2018-18690",
    "CVE-2018-1000026"
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2018-1432)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In the Linux Kernel before version 4.15.8, 4.14.25,
    4.9.87, 4.4.121, 4.1.51, and 3.2.102, an error in the
    '_sctp_make_chunk()' function
    (net/sctp/sm_make_chunk.c) when handling SCTP packets
    length can be exploited to cause a kernel
    crash.(CVE-2018-5803)

  - Linux Linux kernel version at least v4.8 onwards,
    probably well before contains a Insufficient input
    validation vulnerability in bnx2x network card driver
    that can result in DoS: Network card firmware assertion
    takes card off-line. This attack appear to be
    exploitable via An attacker on a must pass a very
    large, specially crafted packet to the bnx2x card. This
    can be done from an untrusted guest
    VM.(CVE-2018-1000026)

  - The Linux kernel is vulnerable to a NULL pointer
    dereference in the
    ext4/mballoc.c:ext4_process_freed_data() function. An
    attacker could trick a legitimate user or a privileged
    attacker could exploit this by mounting a crafted ext4
    image to cause a kernel panic.(CVE-2018-1092)

  - In the function wmi_set_ie() in the Linux kernel the
    length validation code does not handle unsigned integer
    overflow properly. As a result, a large value of the
    aEUR~ie_lenaEURtm argument can cause a buffer overflow and
    thus a memory corruption leading to a system crash or
    other or unspecified impact. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2018-5848)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bound access in
    ext4_get_group_info function, a denial of service, and
    a system crash by mounting and operating on a crafted
    ext4 filesystem image.(CVE-2018-10881)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bounds write and a
    denial of service or unspecified other impact is
    possible by mounting and operating a crafted ext4
    filesystem image.(CVE-2018-10878)

  - A security flaw was found in the
    chap_server_compute_md5() function in the ISCSI target
    code in the Linux kernel in a way an authentication
    request from an ISCSI initiator is processed. An
    unauthenticated remote attacker can cause a stack
    buffer overflow and smash up to 17 bytes of the stack.
    The attack requires the iSCSI target to be enabled on
    the victim host. Depending on how the target's code was
    built (i.e. depending on a compiler, compile flags and
    hardware architecture) an attack may lead to a system
    crash and thus to a denial of service or possibly to a
    non-authorized access to data exported by an iSCSI
    target. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is highly unlikely.(CVE-2018-14633)

  - An issue was discovered in the Linux kernel before
    4.18.6. An information leak in cdrom_ioctl_drive_status
    in drivers/cdrom/cdrom.c could be used by local
    attackers to read kernel memory because a cast from
    unsigned long to int interferes with bounds
    checking.(CVE-2018-16658)

  - In the Linux kernel before 4.17, a local attacker able
    to set attributes on an xfs filesystem could make this
    filesystem non-operational until the next mount by
    triggering an unchecked error condition during an xfs
    attribute change, because xfs_attr_shortform_addname in
    fs/xfs/libxfs/xfs_attr.c mishandles ATTR_REPLACE
    operations with conversion of an attr from short to
    long form.(CVE-2018-18690)

  - It was found that paravirt_patch_call/jump() functions
    in the arch/x86/kernel/paravirt.c in the Linux kernel
    mishandles certain indirect calls, which makes it
    easier for attackers to conduct Spectre-v2 attacks
    against paravirtualized guests.(CVE-2018-15594)

  - A security flaw was found in the Linux kernel in
    drivers/tty/n_tty.c which allows local attackers (ones
    who are able to access pseudo terminals) to lock them
    up and block further usage of any pseudo terminal
    devices due to an EXTPROC versus ICANON confusion in
    TIOCINQ handler.(CVE-2018-18386)

  - An out-of-bounds access issue was discovered in
    yurex_read() in drivers/usb/misc/yurex.c in the Linux
    kernel. A local attacker could use user access
    read/writes with incorrect bounds checking in the yurex
    USB driver to crash the kernel or potentially escalate
    privileges.(CVE-2018-16276)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1432
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dbf3082");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14633");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-5848");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/28");

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

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["kernel-3.10.0-327.62.59.83.h120",
        "kernel-debug-3.10.0-327.62.59.83.h120",
        "kernel-debug-devel-3.10.0-327.62.59.83.h120",
        "kernel-debuginfo-3.10.0-327.62.59.83.h120",
        "kernel-debuginfo-common-x86_64-3.10.0-327.62.59.83.h120",
        "kernel-devel-3.10.0-327.62.59.83.h120",
        "kernel-headers-3.10.0-327.62.59.83.h120",
        "kernel-tools-3.10.0-327.62.59.83.h120",
        "kernel-tools-libs-3.10.0-327.62.59.83.h120",
        "perf-3.10.0-327.62.59.83.h120",
        "python-perf-3.10.0-327.62.59.83.h120"];

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
