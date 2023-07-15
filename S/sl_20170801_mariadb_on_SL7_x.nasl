#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102648);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-5483", "CVE-2016-5617", "CVE-2016-6664", "CVE-2017-3238", "CVE-2017-3243", "CVE-2017-3244", "CVE-2017-3258", "CVE-2017-3265", "CVE-2017-3291", "CVE-2017-3302", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3312", "CVE-2017-3313", "CVE-2017-3317", "CVE-2017-3318", "CVE-2017-3453", "CVE-2017-3456", "CVE-2017-3464", "CVE-2017-3600");

  script_name(english:"Scientific Linux Security Update : mariadb on SL7.x x86_64 (20170801)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following packages have been upgraded to a later upstream version:
mariadb (5.5.56).

Security Fix(es) :

  - It was discovered that the mysql and mysqldump tools did
    not correctly handle database and table names containing
    newline characters. A database user with privileges to
    create databases or tables could cause the mysql command
    to execute arbitrary shell or SQL commands while
    restoring database backup created using the mysqldump
    tool. (CVE-2016-5483, CVE-2017-3600)

  - A flaw was found in the way the mysqld_safe script
    handled creation of error log file. The mysql operating
    system user could use this flaw to escalate their
    privileges to root. (CVE-2016-5617, CVE-2016-6664)

  - Multiple flaws were found in the way the MySQL init
    script handled initialization of the database data
    directory and permission setting on the error log file.
    The mysql operating system user could use these flaws to
    escalate their privileges to root. (CVE-2017-3265)

  - It was discovered that the mysqld_safe script honored
    the ledir option value set in a MySQL configuration
    file. A user able to modify one of the MySQL
    configuration files could use this flaw to escalate
    their privileges to root. (CVE-2017-3291)

  - Multiple flaws were found in the way the mysqld_safe
    script handled creation of error log file. The mysql
    operating system user could use these flaws to escalate
    their privileges to root. (CVE-2017-3312)

  - A flaw was found in the way MySQL client library
    (libmysqlclient) handled prepared statements when server
    connection was lost. A malicious server or a
    man-in-the-middle attacker could possibly use this flaw
    to crash an application using libmysqlclient.
    (CVE-2017-3302)

(CVE-2017-3238, CVE-2017-3243, CVE-2017-3244, CVE-2017-3258,
CVE-2017-3308, CVE-2017-3309, CVE-2017-3313, CVE-2017-3317,
CVE-2017-3318, CVE-2017-3453, CVE-2017-3456, CVE-2017-3464)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1708&L=scientific-linux-errata&F=&S=&P=14039
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61a09e21"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-5.5.56-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-bench-5.5.56-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-debuginfo-5.5.56-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-devel-5.5.56-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-embedded-5.5.56-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-embedded-devel-5.5.56-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-libs-5.5.56-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-server-5.5.56-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mariadb-test-5.5.56-2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb / mariadb-bench / mariadb-debuginfo / mariadb-devel / etc");
}
