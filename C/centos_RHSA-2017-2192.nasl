#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2192 and 
# CentOS Errata and Security Advisory 2017:2192 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102755);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-5483", "CVE-2016-5617", "CVE-2016-6664", "CVE-2017-3238", "CVE-2017-3243", "CVE-2017-3244", "CVE-2017-3258", "CVE-2017-3265", "CVE-2017-3291", "CVE-2017-3302", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3312", "CVE-2017-3313", "CVE-2017-3317", "CVE-2017-3318", "CVE-2017-3453", "CVE-2017-3456", "CVE-2017-3464", "CVE-2017-3600", "CVE-2017-3651");
  script_xref(name:"RHSA", value:"2017:2192");

  script_name(english:"CentOS 7 : mariadb (CESA-2017:2192)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for mariadb is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

MariaDB is a multi-user, multi-threaded SQL database server that is
binary compatible with MySQL.

The following packages have been upgraded to a later upstream version:
mariadb (5.5.56). (BZ#1458933)

Security Fix(es) :

* It was discovered that the mysql and mysqldump tools did not
correctly handle database and table names containing newline
characters. A database user with privileges to create databases or
tables could cause the mysql command to execute arbitrary shell or SQL
commands while restoring database backup created using the mysqldump
tool. (CVE-2016-5483, CVE-2017-3600)

* A flaw was found in the way the mysqld_safe script handled creation
of error log file. The mysql operating system user could use this flaw
to escalate their privileges to root. (CVE-2016-5617, CVE-2016-6664)

* Multiple flaws were found in the way the MySQL init script handled
initialization of the database data directory and permission setting
on the error log file. The mysql operating system user could use these
flaws to escalate their privileges to root. (CVE-2017-3265)

* It was discovered that the mysqld_safe script honored the ledir
option value set in a MySQL configuration file. A user able to modify
one of the MySQL configuration files could use this flaw to escalate
their privileges to root. (CVE-2017-3291)

* Multiple flaws were found in the way the mysqld_safe script handled
creation of error log file. The mysql operating system user could use
these flaws to escalate their privileges to root. (CVE-2017-3312)

* A flaw was found in the way MySQL client library (libmysqlclient)
handled prepared statements when server connection was lost. A
malicious server or a man-in-the-middle attacker could possibly use
this flaw to crash an application using libmysqlclient.
(CVE-2017-3302)

* This update fixes several vulnerabilities in the MariaDB database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2017-3238, CVE-2017-3243, CVE-2017-3244, CVE-2017-3258,
CVE-2017-3308, CVE-2017-3309, CVE-2017-3313, CVE-2017-3317,
CVE-2017-3318, CVE-2017-3453, CVE-2017-3456, CVE-2017-3464)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004369.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bf505b4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6664");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-5.5.56-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-bench-5.5.56-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-devel-5.5.56-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-embedded-5.5.56-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-embedded-devel-5.5.56-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-libs-5.5.56-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-server-5.5.56-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-test-5.5.56-2.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb / mariadb-bench / mariadb-devel / mariadb-embedded / etc");
}
