#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131817);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2018-3058",
    "CVE-2018-3063",
    "CVE-2018-3066",
    "CVE-2018-3081",
    "CVE-2018-3282",
    "CVE-2019-2503",
    "CVE-2019-2529",
    "CVE-2019-2614",
    "CVE-2019-2627",
    "CVE-2019-2737",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2805"
  );

  script_name(english:"EulerOS 2.0 SP5 : mariadb (EulerOS-SA-2019-2543)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the mariadb packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - MariaDB is a community developed branch of MySQL.
    MariaDB is a multi-user, multi-threaded SQL database
    server. It is a client/server implementation consisting
    of a server daemon (mysqld) and many different client
    programs and libraries. The base package contains the
    standard MariaDB/MySQL client programs and generic
    MySQL files.Security Fix(es):Vulnerability in the MySQL
    Server component of Oracle MySQL (subcomponent: Server:
    Security: Privileges). Supported versions that are
    affected are 5.6.43 and prior, 5.7.25 and prior and
    8.0.15 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL
    Server.(CVE-2019-2627)Vulnerability in the MySQL Client
    component of Oracle MySQL (subcomponent: Client
    programs). Supported versions that are affected are
    5.5.60 and prior, 5.6.40 and prior, 5.7.22 and prior
    and 8.0.11 and prior. Difficult to exploit
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Client. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Client as well as unauthorized update, insert or delete
    access to some of MySQL Client accessible
    data.(CVE-2018-3081)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server:
    Connection Handling). Supported versions that are
    affected are 5.6.42 and prior, 5.7.24 and prior and
    8.0.13 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with access to the
    physical communication segment attached to the hardware
    where the MySQL Server executes to compromise MySQL
    Server. Successful attacks of this vulnerability can
    result in unauthorized access to critical data or
    complete access to all MySQL Server accessible data and
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL
    Server.(CVE-2019-2503)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server:
    Optimizer). Supported versions that are affected are
    5.6.42 and prior, 5.7.24 and prior and 8.0.13 and
    prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL
    Server.(CVE-2019-2529)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server:
    Replication). Supported versions that are affected are
    5.6.43 and prior, 5.7.25 and prior and 8.0.15 and
    prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL
    Server.(CVE-2019-2614)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: MyISAM).
    Supported versions that are affected are 5.5.60 and
    prior, 5.6.40 and prior and 5.7.22 and prior. Easily
    exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of MySQL Server accessible
    data.(CVE-2018-3058)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server:
    Security: Privileges). Supported versions that are
    affected are 5.5.60 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.(CVE-2018-3063)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server:
    Options). Supported versions that are affected are
    5.5.60 and prior, 5.6.40 and prior and 5.7.22 and
    prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of
    MySQL Server accessible data as well as unauthorized
    read access to a subset of MySQL Server accessible
    data.(CVE-2018-3066)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server:
    Storage Engines). Supported versions that are affected
    are 5.5.61 and prior, 5.6.41 and prior, 5.7.23 and
    prior and 8.0.12 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.(CVE-2018-3282)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server: XML).
    Supported versions that are affected are 5.6.44 and
    prior, 5.7.26 and prior and 8.0.16 and prior. Easily
    exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server.(CVE-2019-2740)Vulnerability in
    the MySQL Server component of Oracle MySQL
    (subcomponent: Server: Security: Privileges). Supported
    versions that are affected are 5.6.44 and prior, 5.7.26
    and prior and 8.0.16 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    logon to the infrastructure where MySQL Server executes
    to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of M(CVE-2019-2739)Vulnerability in the MySQL
    Server component of Oracle MySQL (subcomponent: Server:
    Parser). Supported versions that are affected are
    5.6.44 and prior, 5.7.26 and prior and 8.0.16 and
    prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL
    Server.(CVE-2019-2805)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server :
    Pluggable Auth). Supported versions that are affected
    are 5.6.44 and prior, 5.7.26 and prior and 8.0.16 and
    prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL
    Server.(CVE-2019-2737)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2543
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d2b4f70");
  script_set_attribute(attribute:"solution", value:
"Update the affected mariadb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3081");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["mariadb-5.5.66-1.eulerosv2r7",
        "mariadb-bench-5.5.66-1.eulerosv2r7",
        "mariadb-devel-5.5.66-1.eulerosv2r7",
        "mariadb-libs-5.5.66-1.eulerosv2r7",
        "mariadb-server-5.5.66-1.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
