#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0085 and 
# CentOS Errata and Security Advisory 2007:0085 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24727);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0001", "CVE-2007-0006");
  script_xref(name:"RHSA", value:"2007:0085");

  script_name(english:"CentOS 4 : kernel (CESA-2007:0085)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and a bug in the
Red Hat Enterprise Linux 4 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for two security issues :

* a flaw in the key serial number collision avoidance algorithm of the
keyctl subsystem that allowed a local user to cause a denial of
service (CVE-2007-0006, Important)

* a flaw in the file watch implementation of the audit subsystems that
allowed a local user to cause a denial of service (panic). To exploit
this flaw a privileged user must have previously created a watch for a
file (CVE-2007-0001, Moderate)

In addition to the security issues described above, a fix for the SCTP
subsystem to address a system crash which may be experienced in Telco
environments has been included.

Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
to the packages associated with their machine architecture and
configurations as listed in this erratum."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013584.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9eaf9296"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013586.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cba915e3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5938198b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-42.0.10.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-42.0.10.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
}
