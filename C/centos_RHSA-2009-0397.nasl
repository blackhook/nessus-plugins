#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0397 and 
# CentOS Errata and Security Advisory 2009:0397 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43737);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1044", "CVE-2009-1169");
  script_xref(name:"RHSA", value:"2009:0397");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2009:0397)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix two security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A memory corruption flaw was discovered in the way Firefox handles XML
files containing an XSLT transform. A remote attacker could use this
flaw to crash Firefox or, potentially, execute arbitrary code as the
user running Firefox. (CVE-2009-1169)

A flaw was discovered in the way Firefox handles certain XUL garbage
collection events. A remote attacker could use this flaw to crash
Firefox or, potentially, execute arbitrary code as the user running
Firefox. (CVE-2009-1044)

For technical details regarding these flaws, refer to the Mozilla
security advisories. You can find a link to the Mozilla advisories in
the References section of this errata.

Firefox users should upgrade to these updated packages, which resolve
these issues. For Red Hat Enterprise Linux 4, they contain backported
patches to the firefox package. For Red Hat Enterprise Linux 5, they
contain backported patches to the xulrunner packages. After installing
the update, Firefox must be restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015756.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?406e64f8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015757.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1b487e2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015820.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50882e36"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015821.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?882cfd5d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/23");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.0.7-3.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.0.7-3.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.0.7-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.0.7-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-unstable-1.9.0.7-3.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / xulrunner / xulrunner-devel / xulrunner-devel-unstable");
}
