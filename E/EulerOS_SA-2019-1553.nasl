#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125006);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-6464",
    "CVE-2014-6469",
    "CVE-2014-6559",
    "CVE-2016-0505",
    "CVE-2016-0546",
    "CVE-2016-0598",
    "CVE-2016-0640",
    "CVE-2016-0641",
    "CVE-2016-0650",
    "CVE-2016-0666",
    "CVE-2016-3452",
    "CVE-2016-3477",
    "CVE-2016-3492",
    "CVE-2016-3521",
    "CVE-2016-3615",
    "CVE-2016-5440",
    "CVE-2016-5444",
    "CVE-2016-5629",
    "CVE-2016-6662",
    "CVE-2016-6663"
  );
  script_bugtraq_id(
    70446,
    70451,
    70487
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : mariadb (EulerOS-SA-2019-1553)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the mariadb packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - Unspecified vulnerability in Oracle MySQL 5.5.49 and
    earlier, 5.6.30 and earlier, and 5.7.12 and earlier and
    MariaDB before 5.5.50, 10.0.x before 10.0.26, and
    10.1.x before 10.1.15 allows local users to affect
    confidentiality, integrity, and availability via
    vectors related to Server: Parser.(CVE-2016-3477)

  - Unspecified vulnerability in Oracle MySQL 5.5.51 and
    earlier, 5.6.32 and earlier, and 5.7.14 and earlier
    allows remote authenticated users to affect
    availability via vectors related to Server:
    Optimizer.(CVE-2016-3492)

  - Unspecified vulnerability in Oracle MySQL 5.5.51 and
    earlier, 5.6.32 and earlier, and 5.7.14 and earlier
    allows remote administrators to affect availability via
    vectors related to Server: Federated.(CVE-2016-5629)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    availability via vectors related to
    Replication.(CVE-2016-0650)

  - Unspecified vulnerability in Oracle MySQL 5.5.49 and
    earlier, 5.6.30 and earlier, and 5.7.12 and earlier and
    MariaDB before 5.5.50, 10.0.x before 10.0.26, and
    10.1.x before 10.1.15 allows remote administrators to
    affect availability via vectors related to Server:
    RBR.(CVE-2016-5440)

  - Unspecified vulnerability in Oracle MySQL 5.5.49 and
    earlier, 5.6.30 and earlier, and 5.7.12 and earlier and
    MariaDB before 5.5.50, 10.0.x before 10.0.26, and
    10.1.x before 10.1.15 allows remote authenticated users
    to affect availability via vectors related to Server:
    Types.(CVE-2016-3521)

  - Unspecified vulnerability in Oracle MySQL 5.5.46 and
    earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB
    before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before
    10.1.10 allows local users to affect confidentiality,
    integrity, and availability via unknown vectors related
    to Client. NOTE: the previous information is from the
    January 2016 CPU. Oracle has not commented on
    third-party claims that these are multiple buffer
    overflows in the mysqlshow tool that allow remote
    database servers to have unspecified impact via a long
    table or database name.(CVE-2016-0546)

  - Unspecified vulnerability in Oracle MySQL 5.5.46 and
    earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB
    before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before
    10.1.10 allows remote authenticated users to affect
    availability via vectors related to DML.(CVE-2016-0598)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.11 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows remote attackers to affect
    confidentiality via vectors related to Server:
    Connection.(CVE-2016-5444)

  - Unspecified vulnerability in Oracle MySQL 5.5.49 and
    earlier, 5.6.30 and earlier, and 5.7.12 and earlier and
    MariaDB before 5.5.50, 10.0.x before 10.0.26, and
    10.1.x before 10.1.15 allows remote authenticated users
    to affect availability via vectors related to Server:
    DML.(CVE-2016-3615)

  - A race condition was found in the way MySQL performed
    MyISAM engine table repair. A database user with shell
    access to the server running mysqld could use this flaw
    to change permissions of arbitrary files writable by
    the mysql system user.(CVE-2016-6663)

  - It was discovered that the MySQL logging functionality
    allowed writing to MySQL configuration files. An
    administrative database user, or a database user with
    FILE privileges, could possibly use this flaw to run
    arbitrary commands with root privileges on the system
    running the database server.(CVE-2016-6662)

  - Unspecified vulnerability in Oracle MySQL 5.5.46 and
    earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB
    before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before
    10.1.10 allows remote authenticated users to affect
    availability via unknown vectors related to
    Options.(CVE-2016-0505)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.11 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows local users to affect
    availability via vectors related to Security:
    Privileges.(CVE-2016-0666)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.39
    and earlier and 5.6.20 and earlier allows remote
    authenticated users to affect availability via vectors
    related to SERVER:OPTIMIZER.(CVE-2014-6469)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    integrity and availability via vectors related to
    DML.(CVE-2016-0640)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows remote attackers to affect
    confidentiality via vectors related to Server:
    Security: Encryption.(CVE-2016-3452)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    confidentiality and availability via vectors related to
    MyISAM.(CVE-2016-0641)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.39
    and earlier and 5.6.20 and earlier allows remote
    authenticated users to affect availability via vectors
    related to SERVER:INNODB DML FOREIGN
    KEYS.(CVE-2014-6464)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.39
    and earlier, and 5.6.20 and earlier, allows remote
    attackers to affect confidentiality via vectors related
    to C API SSL CERTIFICATE HANDLING.(CVE-2014-6559)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1553
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6662e56e");
  script_set_attribute(attribute:"solution", value:
"Update the affected mariadb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["mariadb-5.5.60-1",
        "mariadb-libs-5.5.60-1",
        "mariadb-server-5.5.60-1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
