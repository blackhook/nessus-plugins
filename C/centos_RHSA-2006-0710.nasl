#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0710 and 
# CentOS Errata and Security Advisory 2006:0710 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22879);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-1864", "CVE-2006-2071", "CVE-2006-2935", "CVE-2006-4342", "CVE-2006-4997", "CVE-2006-5174");
  script_xref(name:"RHSA", value:"2006:0710");

  script_name(english:"CentOS 3 : kernel (CESA-2006:0710)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues in the Red
Hat Enterprise Linux 3 kernel are now available.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the security issues
described below :

* a flaw in the IPC shared-memory implementation that allowed a local
user to cause a denial of service (deadlock) that resulted in freezing
the system (CVE-2006-4342, Important)

* an information leak in the copy_from_user() implementation on s390
and s390x platforms that allowed a local user to read arbitrary kernel
memory (CVE-2006-5174, Important)

* a flaw in the ATM subsystem affecting systems with installed ATM
hardware and configured ATM support that allowed a remote user to
cause a denial of service (panic) by accessing socket buffer memory
after it has been freed (CVE-2006-4997, Moderate)

* a directory traversal vulnerability in smbfs that allowed a local
user to escape chroot restrictions for an SMB-mounted filesystem via
'..\\' sequences (CVE-2006-1864, Moderate)

* a flaw in the mprotect system call that allowed enabling write
permission for a read-only attachment of shared memory (CVE-2006-2071,
Moderate)

* a flaw in the DVD handling of the CDROM driver that could be used
together with a custom built USB device to gain root privileges
(CVE-2006-2935, Moderate)

In addition to the security issues described above, a bug fix for a
clock skew problem (which could lead to unintended keyboard repeat
under X11) was also included. The problem only occurred when running
the 32-bit x86 kernel on 64-bit dual-core x86_64 hardware.

Note: The kernel-unsupported package contains various drivers and
modules that are unsupported and therefore might contain security
problems that have not been addressed.

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architecture and
configurations as listed in this erratum."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-October/013332.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e723e2cb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-October/013333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e06a02a7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-October/013334.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f117f13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/20");
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
if (rpm_check(release:"CentOS-3", reference:"kernel-2.4.21-47.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-47.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-doc-2.4.21-47.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-47.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-47.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-47.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-47.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-47.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-47.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-source-2.4.21-47.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-unsupported-2.4.21-47.0.1.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-doc / kernel-hugemem / etc");
}
