#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0978 and 
# CentOS Errata and Security Advisory 2008:0978 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43715);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-0017", "CVE-2008-5014", "CVE-2008-5015", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024");
  script_bugtraq_id(32281);
  script_xref(name:"RHSA", value:"2008:0978");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2008:0978)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated firefox package that fixes various security issues is now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code as the user running Firefox.
(CVE-2008-0017, CVE-2008-5014, CVE-2008-5016, CVE-2008-5017,
CVE-2008-5018, CVE-2008-5019, CVE-2008-5021)

Several flaws were found in the way malformed content was processed. A
web site containing specially crafted content could potentially trick
a Firefox user into surrendering sensitive information.
(CVE-2008-5022, CVE-2008-5023, CVE-2008-5024)

A flaw was found in the way Firefox opened 'file:' URIs. If a file:
URI was loaded in the same tab as a chrome or privileged 'about:'
page, the file: URI could execute arbitrary code with the permissions
of the user running Firefox. (CVE-2008-5015)

For technical details regarding these flaws, please see the Mozilla
security advisories for Firefox 3.0.4. You can find a link to the
Mozilla advisories in the References section.

All firefox users should upgrade to these updated packages, which
contain backported patches that correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015406.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61779cf2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015407.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82346c25"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015434.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5232f8b7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015435.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dad7b61a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015446.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a81184a7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 94, 119, 189, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/14");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-3.0.4-1.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"nss-3.12.1.1-3.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", reference:"nss-devel-3.12.1.1-3.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"devhelp-0.12-20.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"devhelp-devel-0.12-20.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-3.0.4-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-3.12.1.1-3.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.12.1.1-3.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.12.1.1-3.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.12.1.1-3.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.0.4-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.0.4-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-unstable-1.9.0.4-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"yelp-2.16.0-22.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / firefox / nss / nss-devel / etc");
}
