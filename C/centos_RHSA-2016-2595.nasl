#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2595 and 
# CentOS Errata and Security Advisory 2016:2595 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95341);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-3492", "CVE-2016-5612", "CVE-2016-5616", "CVE-2016-5624", "CVE-2016-5626", "CVE-2016-5629", "CVE-2016-6662", "CVE-2016-6663", "CVE-2016-8283");
  script_xref(name:"RHSA", value:"2016:2595");

  script_name(english:"CentOS 7 : mariadb (CESA-2016:2595)");
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
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

MariaDB is a multi-user, multi-threaded SQL database server that is
binary compatible with MySQL.

The following packages have been upgraded to a newer upstream version:
mariadb (5.5.52). (BZ#1304516, BZ#1377974)

Security Fix(es) :

* It was discovered that the MariaDB logging functionality allowed
writing to MariaDB configuration files. An administrative database
user, or a database user with FILE privileges, could possibly use this
flaw to run arbitrary commands with root privileges on the system
running the database server. (CVE-2016-6662)

* A race condition was found in the way MariaDB performed MyISAM
engine table repair. A database user with shell access to the server
running mysqld could use this flaw to change permissions of arbitrary
files writable by the mysql system user. (CVE-2016-6663)

* This update fixes several vulnerabilities in the MariaDB database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2016-3492, CVE-2016-5612, CVE-2016-5616, CVE-2016-5624,
CVE-2016-5626, CVE-2016-5629, CVE-2016-8283)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003624.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6aeacd81"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6662");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-5.5.52-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-bench-5.5.52-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-devel-5.5.52-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-embedded-5.5.52-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-embedded-devel-5.5.52-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-libs-5.5.52-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-server-5.5.52-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-test-5.5.52-1.el7")) flag++;


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
    severity   : SECURITY_HOLE,
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
