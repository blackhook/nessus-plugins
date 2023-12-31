#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:803 and 
# CentOS Errata and Security Advisory 2005:803 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21863);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3120");
  script_bugtraq_id(15117);
  script_xref(name:"RHSA", value:"2005:803");

  script_name(english:"CentOS 3 / 4 : lynx (CESA-2005:803)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated lynx package that corrects a security flaw is now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Lynx is a text-based Web browser.

Ulf Harnhammar discovered a stack overflow bug in Lynx when handling
connections to NNTP (news) servers. An attacker could create a web
page redirecting to a malicious news server which could execute
arbitrary code as the user running lynx. The Common Vulnerabilities
and Exposures project assigned the name CVE-2005-3120 to this issue.

Users should update to this erratum package, which contains a
backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012288.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32cf0cb0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012289.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91ed8dc4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012292.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4e05709"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012293.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11a72566"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012320.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26ff1972"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012321.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?132e0a60"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lynx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lynx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"lynx-2.8.5-11.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"lynx-2.8.5-18.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lynx");
}
