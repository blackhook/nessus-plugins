#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0373 and 
# CentOS Errata and Security Advisory 2009:0373 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43735);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0784");
  script_xref(name:"RHSA", value:"2009:0373");

  script_name(english:"CentOS 4 / 5 : systemtap (CESA-2009:0373)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated systemtap packages that fix a security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SystemTap is an instrumentation infrastructure for systems running
version 2.6 of the Linux kernel. SystemTap scripts can collect system
operations data, greatly simplifying information gathering. Collected
data can then assist in performance measuring, functional testing, and
performance and function problem diagnosis.

A race condition was discovered in SystemTap that could allow users in
the stapusr group to elevate privileges to that of members of the
stapdev group (and hence root), bypassing directory confinement
restrictions and allowing them to insert arbitrary SystemTap kernel
modules. (CVE-2009-0784)

Note: This issue was only exploitable if another SystemTap kernel
module was placed in the 'systemtap/' module directory for the
currently running kernel.

Red Hat would like to thank Erik Sjolund for reporting this issue.

SystemTap users should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015744.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39f7b38f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015745.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?510dd9f4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015814.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?603d5057"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015815.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57fdf488"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-March/015701.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?252adce2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemtap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"systemtap-0.6.2-2.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"systemtap-0.6.2-2.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"systemtap-0.6.2-2.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"systemtap-runtime-0.6.2-2.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"systemtap-runtime-0.6.2-2.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"systemtap-runtime-0.6.2-2.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"systemtap-testsuite-0.6.2-2.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"systemtap-testsuite-0.6.2-2.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"systemtap-testsuite-0.6.2-2.el4_7")) flag++;

if (rpm_check(release:"CentOS-5", reference:"systemtap-0.7.2-3.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-client-0.7.2-3.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-runtime-0.7.2-3.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-server-0.7.2-3.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-testsuite-0.7.2-3.el5_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap / systemtap-client / systemtap-runtime / systemtap-server / etc");
}
