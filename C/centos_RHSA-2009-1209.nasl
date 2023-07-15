#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1209 and 
# CentOS Errata and Security Advisory 2009:1209 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40593);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2417");
  script_bugtraq_id(36032);
  script_xref(name:"RHSA", value:"2009:1209");

  script_name(english:"CentOS 3 / 5 : curl (CESA-2009:1209)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages that fix security issues are now available for
Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and
Dict servers, using any of the supported protocols. cURL is designed
to work without user interaction or any kind of interactivity.

Scott Cantor reported that cURL is affected by the previously
published 'null prefix attack', caused by incorrect handling of NULL
characters in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse cURL into accepting
it by mistake. (CVE-2009-2417)

cURL users should upgrade to these updated packages, which contain a
backported patch to correct these issues. All running applications
using libcurl must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-August/016076.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08353359"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-August/016077.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f87fa1be"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-August/016095.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?329bc440"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-August/016096.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4b2849e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/17");
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
if (! preg(pattern:"^(3|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"curl-7.10.6-10.rhel3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"curl-7.10.6-10.rhel3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"curl-devel-7.10.6-10.rhel3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"curl-devel-7.10.6-10.rhel3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"curl-7.15.5-2.1.el5_3.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"curl-devel-7.15.5-2.1.el5_3.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-devel");
}
