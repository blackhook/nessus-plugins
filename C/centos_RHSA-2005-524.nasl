#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:524 and 
# CentOS Errata and Security Advisory 2005:524 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21837);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1454", "CVE-2005-1455");
  script_xref(name:"RHSA", value:"2005:524");

  script_name(english:"CentOS 3 / 4 : freeradius (CESA-2005:524)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freeradius packages that fix a buffer overflow and possible
SQL injection attacks in the sql module are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

FreeRADIUS is a high-performance and highly configurable free RADIUS
server designed to allow centralized authentication and authorization
for a network.

A buffer overflow bug was found in the way FreeRADIUS escapes data in
a SQL query. An attacker may be able to crash FreeRADIUS if they cause
FreeRADIUS to escape a string containing three or less characters. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-1454 to this issue.

Additionally a bug was found in the way FreeRADIUS escapes SQL data.
It is possible that an authenticated user could execute arbitrary SQL
queries by sending a specially crafted request to FreeRADIUS. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-1455 to this issue.

Users of FreeRADIUS should update to these erratum packages, which
contain backported patches and are not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011892.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a07e7fac"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011894.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f159ba5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011895.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af79e8ec"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011896.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f54d5ca3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011903.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa5b56be"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011904.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7568b3a4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeradius packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/23");
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
if (rpm_check(release:"CentOS-3", reference:"freeradius-1.0.1-1.1.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freeradius-mysql-1.0.1-1.1.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freeradius-postgresql-1.0.1-1.1.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freeradius-unixODBC-1.0.1-1.1.RHEL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"freeradius-1.0.1-3.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freeradius-mysql-1.0.1-3.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freeradius-postgresql-1.0.1-3.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freeradius-unixODBC-1.0.1-3.RHEL4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-mysql / freeradius-postgresql / etc");
}
