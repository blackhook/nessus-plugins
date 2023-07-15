#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0197. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129910);
  script_version("1.5");
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
    "CVE-2019-2627"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : mariadb Multiple Vulnerabilities (NS-SA-2019-0197)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has mariadb packages installed that are affected
by multiple vulnerabilities:

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: MyISAM). Supported versions that
    are affected are 5.5.60 and prior, 5.6.40 and prior and
    5.7.22 and prior. Easily exploitable vulnerability
    allows low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of
    MySQL Server accessible data. CVSS 3.0 Base Score 4.3
    (Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N).
    (CVE-2018-3058)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Security: Privileges).
    Supported versions that are affected are 5.5.60 and
    prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.0 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2018-3063)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Storage Engines). Supported
    versions that are affected are 5.5.61 and prior, 5.6.41
    and prior, 5.7.23 and prior and 8.0.12 and prior. Easily
    exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.0 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2018-3282)

  - Vulnerability in the MySQL Client component of Oracle
    MySQL (subcomponent: Client programs). Supported
    versions that are affected are 5.5.60 and prior, 5.6.40
    and prior, 5.7.22 and prior and 8.0.11 and prior.
    Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Client. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Client as well as unauthorized update,
    insert or delete access to some of MySQL Client
    accessible data. CVSS 3.0 Base Score 5.0 (Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H).
    (CVE-2018-3081)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Options). Supported
    versions that are affected are 5.5.60 and prior, 5.6.40
    and prior and 5.7.22 and prior. Difficult to exploit
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete
    access to some of MySQL Server accessible data as well
    as unauthorized read access to a subset of MySQL Server
    accessible data. CVSS 3.0 Base Score 3.3
    (Confidentiality and Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N).
    (CVE-2018-3066)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Connection Handling).
    Supported versions that are affected are 5.6.42 and
    prior, 5.7.24 and prior and 8.0.13 and prior. Difficult
    to exploit vulnerability allows low privileged attacker
    with access to the physical communication segment
    attached to the hardware where the MySQL Server executes
    to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized access to
    critical data or complete access to all MySQL Server
    accessible data and unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 6.4 (Confidentiality and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H).
    (CVE-2019-2503)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Replication). Supported
    versions that are affected are 5.6.43 and prior, 5.7.25
    and prior and 8.0.15 and prior. Difficult to exploit
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 4.4 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2019-2614)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Security: Privileges).
    Supported versions that are affected are 5.6.43 and
    prior, 5.7.25 and prior and 8.0.15 and prior. Easily
    exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.0 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2019-2627)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Optimizer). Supported
    versions that are affected are 5.6.42 and prior, 5.7.24
    and prior and 8.0.13 and prior. Easily exploitable
    vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 6.5 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2019-2529)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0197");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL mariadb packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3081");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "mariadb-5.5.64-1.el7",
    "mariadb-bench-5.5.64-1.el7",
    "mariadb-debuginfo-5.5.64-1.el7",
    "mariadb-devel-5.5.64-1.el7",
    "mariadb-embedded-5.5.64-1.el7",
    "mariadb-embedded-devel-5.5.64-1.el7",
    "mariadb-libs-5.5.64-1.el7",
    "mariadb-server-5.5.64-1.el7",
    "mariadb-test-5.5.64-1.el7"
  ],
  "CGSL MAIN 5.04": [
    "mariadb-5.5.64-1.el7",
    "mariadb-bench-5.5.64-1.el7",
    "mariadb-debuginfo-5.5.64-1.el7",
    "mariadb-devel-5.5.64-1.el7",
    "mariadb-embedded-5.5.64-1.el7",
    "mariadb-embedded-devel-5.5.64-1.el7",
    "mariadb-libs-5.5.64-1.el7",
    "mariadb-server-5.5.64-1.el7",
    "mariadb-test-5.5.64-1.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
