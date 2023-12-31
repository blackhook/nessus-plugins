#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:663 and 
# CentOS Errata and Security Advisory 2005:663 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21849);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0181", "CVE-2004-1056", "CVE-2005-0124", "CVE-2005-0136", "CVE-2005-0179", "CVE-2005-0210", "CVE-2005-0400", "CVE-2005-0504", "CVE-2005-0756", "CVE-2005-0815", "CVE-2005-1761", "CVE-2005-1762", "CVE-2005-1767", "CVE-2005-1768", "CVE-2005-2456", "CVE-2005-2490", "CVE-2005-2553", "CVE-2005-2555", "CVE-2005-3273", "CVE-2005-3274");
  script_xref(name:"RHSA", value:"2005:663");

  script_name(english:"CentOS 3 : kernel (CESA-2005:663)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages are now available as part of ongoing support
and maintenance of Red Hat Enterprise Linux version 3. This is the
sixth regular update.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

This is the sixth regular kernel update to Red Hat Enterprise Linux 3.

New features introduced by this update include :

  - diskdump support on HP Smart Array devices -
    netconsole/netdump support over bonded interfaces - new
    chipset and device support via PCI table updates -
    support for new 'oom-kill' and 'kscand_work_percent'
    sysctls - support for dual core processors and ACPI
    Power Management timers on AMD64 and Intel EM64T systems

There were many bug fixes in various parts of the kernel. The ongoing
effort to resolve these problems has resulted in a marked improvement
in the reliability and scalability of Red Hat Enterprise Linux 3.

There were numerous driver updates and security fixes (elaborated
below). Other key areas affected by fixes in this update include
kswapd, inode handling, the SATA subsystem, diskdump handling,
ptrace() syscall support, and signal handling.

The following device drivers have been upgraded to new versions :

3w-9xxx ---- 2.24.03.008RH cciss ------ 2.4.58.RH1 e100 -------
3.4.8-k2 e1000 ------ 6.0.54-k2 emulex ----- 7.3.2 fusion -----
2.06.16i.01 iscsi ------ 3.6.2.1 ipmi ------- 35.4 lpfcdfc ---- 1.2.1
qlogic ----- 7.05.00-RH1 tg3 -------- 3.27RH

The following security bugs were fixed in this update :

  - a flaw in syscall argument checking on Itanium systems
    that allowed a local user to cause a denial of service
    (crash) (CVE-2005-0136)

  - a flaw in stack expansion that allowed a local user of
    mlockall() to cause a denial of service (memory
    exhaustion) (CVE-2005-0179)

  - a small memory leak in network packet defragmenting that
    allowed a remote user to cause a denial of service
    (memory exhaustion) on systems using netfilter
    (CVE-2005-0210)

  - flaws in ptrace() syscall handling on AMD64 and Intel
    EM64T systems that allowed a local user to cause a
    denial of service (crash) (CVE-2005-0756, CVE-2005-1762,
    CVE-2005-2553)

  - flaws in ISO-9660 file system handling that allowed the
    mounting of an invalid image on a CD-ROM to cause a
    denial of service (crash) or potentially execute
    arbitrary code (CVE-2005-0815)

  - a flaw in ptrace() syscall handling on Itanium systems
    that allowed a local user to cause a denial of service
    (crash) (CVE-2005-1761)

  - a flaw in the alternate stack switching on AMD64 and
    Intel EM64T systems that allowed a local user to cause a
    denial of service (crash) (CVE-2005-1767)

  - race conditions in the ia32-compat support for exec()
    syscalls on AMD64, Intel EM64T, and Itanium systems that
    could allow a local user to cause a denial of service
    (crash) (CVE-2005-1768)

  - flaws in IPSEC network handling that allowed a local
    user to cause a denial of service or potentially gain
    privileges (CVE-2005-2456, CVE-2005-2555)

  - a flaw in sendmsg() syscall handling on 64-bit systems
    that allowed a local user to cause a denial of service
    or potentially gain privileges (CVE-2005-2490)

  - flaws in unsupported modules that allowed
    denial-of-service attacks (crashes) or local privilege
    escalations on systems using the drm, coda, or moxa
    modules (CVE-2004-1056, CVE-2005-0124, CVE-2005-0504)

  - potential leaks of kernel data from jfs and ext2 file
    system handling (CVE-2004-0181, CVE-2005-0400)

Note: The kernel-unsupported package contains various drivers and
modules that are unsupported and therefore might contain security
problems that have not been addressed.

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012214.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c562b3df"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012233.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0588dc8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24cca25a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"kernel-2.4.21-37.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-37.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-doc-2.4.21-37.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-37.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-37.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-37.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-37.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-37.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-37.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-source-2.4.21-37.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-unsupported-2.4.21-37.EL")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-doc / kernel-hugemem / etc");
}
