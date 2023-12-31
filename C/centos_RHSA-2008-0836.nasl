#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0836 and 
# CentOS Errata and Security Advisory 2008:0836 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34051);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-3281");
  script_xref(name:"RHSA", value:"2008:0836");

  script_name(english:"CentOS 3 / 4 / 5 : libxml2 (CESA-2008:0836)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix a security issue are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

[Updated 26th August 2008] The original fix used in this errata caused
some applications using the libxml2 library in an unexpected way to
crash when used with updated libxml2 packages. We have updated the
packages for Red Hat Enterprise Linux 3, 4 and 5 to use a different
fix that does not break affected applications.

The libxml2 packages provide a library that allows you to manipulate
XML files. It includes support to read, modify, and write XML and HTML
files.

A denial of service flaw was found in the way libxml2 processes
certain content. If an application linked against libxml2 processes
malformed XML content, it could cause the application to stop
responding. (CVE-2008-3281)

Red Hat would like to thank Andreas Solberg for responsibly disclosing
this issue.

All users of libxml2 are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015196.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3fec53a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015198.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eebbb2be"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015209.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c8c39ca"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015210.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?221b0604"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015213.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9edc3cb5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-August/015214.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8705441"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libxml2-2.5.10-11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"libxml2-2.5.10-10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libxml2-2.5.10-11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libxml2-devel-2.5.10-11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"libxml2-devel-2.5.10-10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libxml2-devel-2.5.10-11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libxml2-python-2.5.10-11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"libxml2-python-2.5.10-10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libxml2-python-2.5.10-11")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxml2-2.6.16-12.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxml2-devel-2.6.16-12.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxml2-python-2.6.16-12.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libxml2-2.6.26-2.1.2.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-devel-2.6.26-2.1.2.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-python-2.6.26-2.1.2.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-devel / libxml2-python");
}
