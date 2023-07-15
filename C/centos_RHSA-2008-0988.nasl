#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0988 and 
# CentOS Errata and Security Advisory 2008:0988 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37692);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-4225", "CVE-2008-4226");
  script_xref(name:"RHSA", value:"2008:0988");

  script_name(english:"CentOS 3 / 4 / 5 : libxml2 (CESA-2008:0988)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix security issues are now available
for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

libxml2 is a library for parsing and manipulating XML files. It
includes support for reading, modifying, and writing XML and HTML
files.

An integer overflow flaw causing a heap-based buffer overflow was
found in the libxml2 XML parser. If an application linked against
libxml2 processed untrusted, malformed XML content, it could cause the
application to crash or, possibly, execute arbitrary code.
(CVE-2008-4226)

A denial of service flaw was discovered in the libxml2 XML parser. If
an application linked against libxml2 processed untrusted, malformed
XML content, it could cause the application to enter an infinite loop.
(CVE-2008-4225)

Red Hat would like to thank Drew Yao of the Apple Product Security
team for reporting these issues.

Users of libxml2 are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?670920aa"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91ed551d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a556f096"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015415.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2da5874"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015416.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dbbca13"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015417.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0db6cac8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015426.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e1df22d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015427.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5784e79b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015430.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?133372e4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015431.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff8d4dd3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"libxml2-2.5.10-14")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libxml2-devel-2.5.10-14")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libxml2-python-2.5.10-14")) flag++;

if (rpm_check(release:"CentOS-4", reference:"libxml2-2.6.16-12.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libxml2-devel-2.6.16-12.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libxml2-python-2.6.16-12.6")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libxml2-2.6.26-2.1.2.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-devel-2.6.26-2.1.2.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-python-2.6.26-2.1.2.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-devel / libxml2-python");
}
