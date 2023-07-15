#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125007);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2014-0001",
    "CVE-2014-6507",
    "CVE-2015-3152",
    "CVE-2016-0596",
    "CVE-2016-0597",
    "CVE-2016-0600",
    "CVE-2016-0606",
    "CVE-2016-0608",
    "CVE-2016-0609",
    "CVE-2016-0616",
    "CVE-2016-0643",
    "CVE-2016-0644",
    "CVE-2016-0646",
    "CVE-2016-0647",
    "CVE-2016-0648",
    "CVE-2016-0649",
    "CVE-2016-5612",
    "CVE-2016-5626",
    "CVE-2017-3302"
  );
  script_bugtraq_id(65298, 70550, 74398);

  script_name(english:"EulerOS Virtualization 3.0.1.0 : mariadb (EulerOS-SA-2019-1554)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the mariadb packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.11 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows local users to affect
    confidentiality via vectors related to
    DML.(CVE-2016-0643)

  - Unspecified vulnerability in Oracle MySQL 5.5.46 and
    earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB
    before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before
    10.1.10 allows remote authenticated users to affect
    availability via vectors related to UDF.(CVE-2016-0608)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    availability via vectors related to DDL.(CVE-2016-0644)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.39
    and earlier, and 5.6.20 and earlier, allows remote
    authenticated users to affect confidentiality,
    integrity, and availability via vectors related to
    SERVER:DML.(CVE-2014-6507)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    availability via vectors related to DML.(CVE-2016-0646)

  - Unspecified vulnerability in Oracle MySQL 5.5.46 and
    earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB
    before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before
    10.1.10 allows remote authenticated users to affect
    availability via unknown vectors related to
    InnoDB.(CVE-2016-0600)

  - Unspecified vulnerability in Oracle MySQL 5.5.46 and
    earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB
    before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before
    10.1.10 allows remote authenticated users to affect
    availability via unknown vectors related to
    Optimizer.(CVE-2016-0597)

  - Buffer overflow in client/mysql.cc in Oracle MySQL and
    MariaDB before 5.5.35 allows remote database servers to
    cause a denial of service (crash) and possibly execute
    arbitrary code via a long server version
    string.(CVE-2014-0001)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.11 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows local users to affect
    availability via vectors related to PS.(CVE-2016-0648)

  - Unspecified vulnerability in Oracle MySQL 5.5.46 and
    earlier and 5.6.27 and earlier and MariaDB before
    5.5.47, 10.0.x before 10.0.23, and 10.1.x before
    10.1.10 allows remote authenticated users to affect
    availability via vectors related to DML.(CVE-2016-0596)

  - Unspecified vulnerability in Oracle MySQL 5.5.46 and
    earlier and MariaDB before 5.5.47, 10.0.x before
    10.0.23, and 10.1.x before 10.1.10 allows remote
    authenticated users to affect availability via unknown
    vectors related to Optimizer.(CVE-2016-0616)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    availability via vectors related to PS.(CVE-2016-0649)

  - It was found that the MySQL client library permitted
    but did not require a client to use SSL/TLS when
    establishing a secure connection to a MySQL server
    using the ''--ssl'' option. A man-in-the-middle
    attacker could use this flaw to strip the SSL/TLS
    protection from a connection between a client and a
    server.(CVE-2015-3152)

  - Unspecified vulnerability in Oracle MySQL 5.5.50 and
    earlier, 5.6.31 and earlier, and 5.7.13 and earlier
    allows remote authenticated users to affect
    availability via vectors related to DML.(CVE-2016-5612)

  - Unspecified vulnerability in Oracle MySQL 5.5.46 and
    earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB
    before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before
    10.1.10 allows remote authenticated users to affect
    integrity via unknown vectors related to
    encryption.(CVE-2016-0606)

  - Unspecified vulnerability in Oracle MySQL 5.5.51 and
    earlier, 5.6.32 and earlier, and 5.7.14 and earlier
    allows remote authenticated users to affect
    availability via vectors related to GIS.(CVE-2016-5626)

  - Unspecified vulnerability in Oracle MySQL 5.5.46 and
    earlier, 5.6.27 and earlier, and 5.7.9 and MariaDB
    before 5.5.47, 10.0.x before 10.0.23, and 10.1.x before
    10.1.10 allows remote authenticated users to affect
    availability via unknown vectors related to
    privileges.(CVE-2016-0609)

  - A flaw was found in the way MySQL client library
    (libmysqlclient) handled prepared statements when
    server connection was lost. A malicious server or a
    man-in-the-middle attacker could possibly use this flaw
    to crash an application using
    libmysqlclient.(CVE-2017-3302)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.11 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows local users to affect
    availability via vectors related to FTS.(CVE-2016-0647)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1554
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f05de522");
  script_set_attribute(attribute:"solution", value:
"Update the affected mariadb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0001");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-3152");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/10");
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

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
