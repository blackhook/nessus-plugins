#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103007);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-5483",
    "CVE-2016-5617",
    "CVE-2016-6664",
    "CVE-2017-3238",
    "CVE-2017-3243",
    "CVE-2017-3244",
    "CVE-2017-3258",
    "CVE-2017-3265",
    "CVE-2017-3291",
    "CVE-2017-3302",
    "CVE-2017-3308",
    "CVE-2017-3309",
    "CVE-2017-3312",
    "CVE-2017-3313",
    "CVE-2017-3317",
    "CVE-2017-3318",
    "CVE-2017-3453",
    "CVE-2017-3456",
    "CVE-2017-3464",
    "CVE-2017-3600",
    "CVE-2017-3651"
  );

  script_name(english:"EulerOS 2.0 SP1 : mariadb (EulerOS-SA-2017-1169)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the mariadb packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - It was discovered that the mysql and mysqldump tools
    did not correctly handle database and table names
    containing newline characters. A database user with
    privileges to create databases or tables could cause
    the mysql command to execute arbitrary shell or SQL
    commands while restoring database backup created using
    the mysqldump tool. (CVE-2016-5483, CVE-2017-3600)

  - A flaw was found in the way the mysqld_safe script
    handled creation of error log file. The mysql operating
    system user could use this flaw to escalate their
    privileges to root. (CVE-2016-5617, CVE-2016-6664)

  - Multiple flaws were found in the way the MySQL init
    script handled initialization of the database data
    directory and permission setting on the error log file.
    The mysql operating system user could use these flaws
    to escalate their privileges to root. (CVE-2017-3265)

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
    (libmysqlclient) handled prepared statements when
    server connection was lost. A malicious server or a
    man-in-the-middle attacker could possibly use this flaw
    to crash an application using libmysqlclient.
    (CVE-2017-3302)

  - This update fixes several vulnerabilities in the
    MariaDB database server. Information about these flaws
    can be found on the Oracle Critical Patch Update
    Advisory page, listed in the References section.
    (CVE-2017-3238, CVE-2017-3243, CVE-2017-3244,
    CVE-2017-3258, CVE-2017-3308, CVE-2017-3309,
    CVE-2017-3313, CVE-2017-3317, CVE-2017-3318,
    CVE-2017-3453, CVE-2017-3456, CVE-2017-3464)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1169
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c88bd5d");
  script_set_attribute(attribute:"solution", value:
"Update the affected mariadb packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["mariadb-5.5.56-2",
        "mariadb-bench-5.5.56-2",
        "mariadb-devel-5.5.56-2",
        "mariadb-embedded-5.5.56-2",
        "mariadb-libs-5.5.56-2",
        "mariadb-server-5.5.56-2",
        "mariadb-test-5.5.56-2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
