#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:348 and 
# CentOS Errata and Security Advisory 2005:348 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21926);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
  script_xref(name:"RHSA", value:"2005:348");

  script_name(english:"CentOS 3 : mysql-server (CESA-2005:348)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql-server packages that fix several vulnerabilities are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server.

This update fixes several security risks in the MySQL server.

Stefano Di Paola discovered two bugs in the way MySQL handles
user-defined functions. A user with the ability to create and execute
a user defined function could potentially execute arbitrary code on
the MySQL server. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the names CVE-2005-0709 and CVE-2005-0710
to these issues.

Stefano Di Paola also discovered a bug in the way MySQL creates
temporary tables. A local user could create a specially crafted
symlink which could result in the MySQL server overwriting a file
which it has write access to. The Common Vulnerabilities and Exposures
project has assigned the name CVE-2005-0711 to this issue.

All users of the MySQL server are advised to upgrade to these updated
packages, which contain fixes for these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011535.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85e7fe6b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011536.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?992d5b7b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011540.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96375831"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"mysql-3.23.58-16.RHEL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"mysql-bench-3.23.58-16.RHEL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"mysql-devel-3.23.58-16.RHEL3.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mysql-server-3.23.58-16.RHEL3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-server");
}
