#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0169 and 
# CentOS Errata and Security Advisory 2007:0169 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25126);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0771", "CVE-2007-1000", "CVE-2007-1388");
  script_xref(name:"RHSA", value:"2007:0169");

  script_name(english:"CentOS 5 : Kernel (CESA-2007:0169)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix security issues and bugs in the Red
Hat Enterprise Linux 5 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the following security
issues :

* a flaw in the IPv6 socket option handling that allowed a local user
to read arbitrary kernel memory (CVE-2007-1000, Important).

* a flaw in the IPv6 socket option handling that allowed a local user
to cause a denial of service (CVE-2007-1388, Important).

* a flaw in the utrace support that allowed a local user to cause a
denial of service (CVE-2007-0771, Important).

In addition to the security issues described above, a fix for a memory
leak in the audit subsystem and a fix for a data corruption bug on
s390 systems have been included.

Red Hat Enterprise Linux 5 users are advised to upgrade to these
erratum packages, which are not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013697.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df709a80"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94e9034a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/02");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-8.1.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-8.1.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-8.1.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-devel-2.6.18-8.1.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-doc-2.6.18-8.1.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-headers-2.6.18-8.1.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-xen-2.6.18-8.1.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-xen-devel-2.6.18-8.1.3.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-devel / kernel-doc / etc");
}
