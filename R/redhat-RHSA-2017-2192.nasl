#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2192. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102152);
  script_version("3.15");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-5483", "CVE-2016-5617", "CVE-2016-6664", "CVE-2017-3238", "CVE-2017-3243", "CVE-2017-3244", "CVE-2017-3258", "CVE-2017-3265", "CVE-2017-3291", "CVE-2017-3302", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3312", "CVE-2017-3313", "CVE-2017-3317", "CVE-2017-3318", "CVE-2017-3453", "CVE-2017-3456", "CVE-2017-3464", "CVE-2017-3600", "CVE-2017-3651");
  script_xref(name:"RHSA", value:"2017:2192");

  script_name(english:"RHEL 7 : mariadb (RHSA-2017:2192)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3395ff0b"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-5553-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-5553-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-5554-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-5554-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-5555-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-5555-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-5556-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-5556-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3651"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2192";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mariadb-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mariadb-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mariadb-bench-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mariadb-bench-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mariadb-debuginfo-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mariadb-devel-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mariadb-embedded-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mariadb-embedded-devel-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mariadb-libs-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mariadb-server-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mariadb-server-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mariadb-test-5.5.56-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mariadb-test-5.5.56-2.el7")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb / mariadb-bench / mariadb-debuginfo / mariadb-devel / etc");
  }
}
