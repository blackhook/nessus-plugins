#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124994);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2017-3641",
    "CVE-2017-3653",
    "CVE-2018-2755",
    "CVE-2018-2761",
    "CVE-2018-2771",
    "CVE-2018-2781",
    "CVE-2018-2813",
    "CVE-2018-2817",
    "CVE-2018-2819"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : mariadb (EulerOS-SA-2019-1541)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the mariadb packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - MariaDB is a community developed branch of
    MySQL.MariaDB is a multi-user, multi-threaded SQL
    database server.It is a client/server implementation
    consisting of a server daemon (mysqld) and many
    different client programs and libraries. The base
    package contains the standard MariaDB/MySQL client
    programs and generic MySQL files.Security
    Fix(es):Vulnerability in the MySQL Server component of
    Oracle MySQL (subcomponent: Client programs). Supported
    versions that are affected are 5.5.59 and prior, 5.6.39
    and prior and 5.7.21 and prior. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.(CVE-2018-2761)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server:
    Replication). Supported versions that are affected are
    5.5.59 and prior, 5.6.39 and prior and 5.7.21 and
    prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with logon to the
    infrastructure where MySQL Server executes to
    compromise MySQL Server. Successful attacks require
    human interaction from a person other than the attacker
    and while the vulnerability is in MySQL Server, attacks
    may significantly impact additional products.
    Successful attacks of this vulnerability can result in
    takeover of MySQL Server.(CVE-2018-2755)Vulnerability
    in the MySQL Server component of Oracle MySQL
    (subcomponent: Server: Locking). Supported versions
    that are affected are 5.5.59 and prior, 5.6.39 and
    prior and 5.7.21 and prior. Difficult to exploit
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.(CVE-2018-2771)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: InnoDB).
    Supported versions that are affected are 5.5.59 and
    prior, 5.6.39 and prior and 5.7.21 and prior. Easily
    exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server.(CVE-2018-2819)Vulnerability in
    the MySQL Server component of Oracle MySQL
    (subcomponent: Server: Optimizer). Supported versions
    that are affected are 5.5.59 and prior, 5.6.39 and
    prior and 5.7.21 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.(CVE-2018-2781)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server: DDL).
    Supported versions that are affected are 5.5.59 and
    prior, 5.6.39 and prior and 5.7.21 and prior. Easily
    exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized read access to
    a subset of MySQL Server accessible
    data.(CVE-2018-2813)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server: DDL).
    Supported versions that are affected are 5.5.59 and
    prior, 5.6.39 and prior and 5.7.21 and prior. Easily
    exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server.(CVE-2018-2817)Vulnerability in
    the MySQL Server component of Oracle MySQL
    (subcomponent: Server: DML). Supported versions that
    are affected are 5.5.56 and earlier, 5.6.36 and earlier
    and 5.7.18 and earlier. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.(CVE-2017-3641)Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server: DDL).
    Supported versions that are affected are 5.5.56 and
    earlier, 5.6.36 and earlier and 5.7.18 and earlier.
    Difficult to exploit vulnerability allows low
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of
    MySQL Server accessible data.(CVE-2017-3653)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1541
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66c1c9bb");
  script_set_attribute(attribute:"solution", value:
"Update the affected mariadb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2813");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2755");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

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
