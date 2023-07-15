#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124823);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-4563",
    "CVE-2014-6418",
    "CVE-2014-7145",
    "CVE-2014-7975",
    "CVE-2014-9683",
    "CVE-2017-1000365",
    "CVE-2017-12146",
    "CVE-2017-9076",
    "CVE-2018-13406",
    "CVE-2018-18386"
  );
  script_bugtraq_id(
    63702,
    69867,
    70314,
    70393,
    72643
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1500)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The IPv6 DCCP implementation in the Linux kernel
    mishandles inheritance, which allows local users to
    cause a denial of service or possibly have unspecified
    other impact via crafted system calls, a related issue
    to CVE-2017-8890. An unprivileged local user could use
    this flaw to induce kernel memory corruption on the
    system, leading to a crash. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2017-9076i1/4%0

  - It was found that the driver_override implementation in
    base/platform.c in the Linux kernel is susceptible to
    race condition when different threads are reading vs
    storing a different driver override.(CVE-2017-12146i1/4%0

  - The Linux Kernel imposes a size restriction on the
    arguments and environmental strings passed through
    RLIMIT_STACK/RLIMIT_INFINITY, but does not take the
    argument and environment pointers into account, which
    allows attackers to bypass this
    limitation.(CVE-2017-1000365i1/4%0

  - A buffer overflow flaw was found in the way the Linux
    kernel's eCryptfs implementation decoded encrypted file
    names. A local, unprivileged user could use this flaw
    to crash the system or, potentially, escalate their
    privileges on the system.(CVE-2014-9683i1/4%0

  - The Linux kernel was found vulnerable to an integer
    overflow in the
    drivers/video/fbdev/uvesafb.c:uvesafb_setcmap()
    function. The vulnerability could result in local
    attackers being able to crash the kernel or potentially
    elevate privileges.(CVE-2018-13406i1/4%0

  - net/ceph/auth_x.c in Ceph, as used in the Linux kernel
    before 3.16.3, does not properly validate auth replies,
    which allows remote attackers to cause a denial of
    service (system crash) or possibly have unspecified
    other impact via crafted data from the IP address of a
    Ceph Monitor.(CVE-2014-6418i1/4%0

  - A NULL pointer dereference flaw was found in the way
    the Linux kernel's Common Internet File System (CIFS)
    implementation handled mounting of file system shares.
    A remote attacker could use this flaw to crash a client
    system that would mount a file system share from a
    malicious server.(CVE-2014-7145i1/4%0

  - The udp6_ufo_fragment function in
    net/ipv6/udp_offload.c in the Linux kernel through
    3.12, when UDP Fragmentation Offload (UFO) is enabled,
    does not properly perform a certain size comparison
    before inserting a fragment header, which allows remote
    attackers to cause a denial of service (panic) via a
    large IPv6 UDP packet, as demonstrated by use of the
    Token Bucket Filter (TBF) queueing
    discipline.(CVE-2013-4563i1/4%0

  - The do_umount function in fs/namespace.c in the Linux
    kernel through 3.17 does not require the CAP_SYS_ADMIN
    capability for do_remount_sb calls that change the root
    filesystem to read-only, which allows local users to
    cause a denial of service (loss of writability) by
    making certain unshare system calls, clearing the /
    MNT_LOCKED flag, and making an MNT_FORCE umount system
    call.(CVE-2014-7975i1/4%0

  - drivers/tty/n_tty.c in the Linux kernel before 4.14.11
    allows local attackers (who are able to access pseudo
    terminals) to hang/block further usage of any pseudo
    terminal devices due to an EXTPROC versus ICANON
    confusion in TIOCINQ.(CVE-2018-18386i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1500
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fbf4f5d");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13406");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

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
