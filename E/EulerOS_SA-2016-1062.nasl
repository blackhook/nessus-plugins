#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99824);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-3492",
    "CVE-2016-5612",
    "CVE-2016-5616",
    "CVE-2016-5624",
    "CVE-2016-5626",
    "CVE-2016-5629",
    "CVE-2016-6662",
    "CVE-2016-6663",
    "CVE-2016-8283"
  );

  script_name(english:"EulerOS 2.0 SP1 : mariadb (EulerOS-SA-2016-1062)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the mariadb packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Unspecified vulnerability in Oracle MySQL 5.5.51 and
    earlier, 5.6.32 and earlier, and 5.7.14 and earlier
    allows remote authenticated users to affect
    availability via vectors related to Server:
    Optimizer.(CVE-2016-3492)

  - Unspecified vulnerability in Oracle MySQL 5.5.50 and
    earlier, 5.6.31 and earlier, and 5.7.13 and earlier
    allows remote authenticated users to affect
    availability via vectors related to DML.(CVE-2016-5612)

  - Unspecified vulnerability in Oracle MySQL 5.5.51 and
    earlier, 5.6.32 and earlier, and 5.7.14 and earlier
    allows local users to affect confidentiality,
    integrity, and availability via vectors related to
    Server: MyISAM.(CVE-2016-5616i1/4%0

  - Unspecified vulnerability in Oracle MySQL 5.5.51 and
    earlier allows remote authenticated users to affect
    availability via vectors related to
    DML.i1/4^CVE-2016-5624i1/4%0

  - Unspecified vulnerability in Oracle MySQL 5.5.51 and
    earlier, 5.6.32 and earlier, and 5.7.14 and earlier
    allows remote authenticated users to affect
    availability via vectors related to
    GIS.i1/4^CVE-2016-5626i1/4%0

  - Unspecified vulnerability in Oracle MySQL 5.5.51 and
    earlier, 5.6.32 and earlier, and 5.7.14 and earlier
    allows remote administrators to affect availability via
    vectors related to Server:
    Federated.i1/4^CVE-2016-5629i1/4%0

  - Oracle MySQL through 5.5.52, 5.6.x through 5.6.33, and
    5.7.x through 5.7.15 MariaDB before 5.5.51, 10.0.x
    before 10.0.27, and 10.1.x before 10.1.17 and Percona
    Server before 5.5.51-38.1, 5.6.x before 5.6.32-78.0,
    and 5.7.x before 5.7.14-7 allow local users to create
    arbitrary configurations and bypass certain protection
    mechanisms by setting general_log_file to a my.cnf
    configuration. NOTE: this can be leveraged to execute
    arbitrary code with root privileges by setting
    malloc_lib.i1/4^CVE-2016-6662i1/4%0

  - A race condition was found in the way MySQL performed
    MyISAM engine table repair. A database user with shell
    access to the server running mysqld could use this flaw
    to change permissions of arbitrary files writable by
    the mysql system user.i1/4^CVE-2016-6663i1/4%0

  - Unspecified vulnerability in Oracle MySQL 5.5.51 and
    earlier, 5.6.32 and earlier, and 5.7.14 and earlier
    allows remote authenticated users to affect
    availability via vectors related to Server:
    Types.i1/4^CVE-2016-8283i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1062
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6d2a717");
  script_set_attribute(attribute:"solution", value:
"Update the affected mariadb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");

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

pkgs = ["mariadb-5.5.52-1",
        "mariadb-bench-5.5.52-1",
        "mariadb-devel-5.5.52-1",
        "mariadb-embedded-5.5.52-1",
        "mariadb-libs-5.5.52-1",
        "mariadb-server-5.5.52-1",
        "mariadb-test-5.5.52-1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
