#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1095 and 
# CentOS Errata and Security Advisory 2009:1095 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43755);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841", "CVE-2009-2043");
  script_xref(name:"RHSA", value:"2009:1095");

  script_name(english:"CentOS 5 : firefox (CESA-2009:1095)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code as the user running Firefox.
(CVE-2009-1392, CVE-2009-1832, CVE-2009-1833, CVE-2009-1837,
CVE-2009-1838, CVE-2009-1841)

Multiple flaws were found in the processing of malformed, local file
content. If a user loaded malicious, local content via the file://
URL, it was possible for that content to access other local data.
(CVE-2009-1835, CVE-2009-1839)

A script, privilege elevation flaw was found in the way Firefox loaded
XML User Interface Language (XUL) scripts. Firefox and certain add-ons
could load malicious content when certain policy checks did not
happen. (CVE-2009-1840)

A flaw was found in the way Firefox displayed certain Unicode
characters in International Domain Names (IDN). If an IDN contained
invalid characters, they may have been displayed as spaces, making it
appear to the user that they were visiting a trusted site.
(CVE-2009-1834)

A flaw was found in the way Firefox handled error responses returned
from proxy servers. If an attacker is able to conduct a
man-in-the-middle attack against a Firefox instance that is using a
proxy server, they may be able to steal sensitive information from the
site the user is visiting. (CVE-2009-1836)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.0.11. You can find a link to the
Mozilla advisories in the References section of this errata.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.0.11, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015993.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12877242"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015994.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74dda8c1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 200, 264, 287, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/19");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"firefox-3.0.11-2.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.0.11-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.0.11-3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-unstable-1.9.0.11-3.el5")) flag++;


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
