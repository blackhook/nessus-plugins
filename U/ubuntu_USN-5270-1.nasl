#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5270-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157356);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-21245",
    "CVE-2022-21249",
    "CVE-2022-21253",
    "CVE-2022-21254",
    "CVE-2022-21256",
    "CVE-2022-21264",
    "CVE-2022-21265",
    "CVE-2022-21270",
    "CVE-2022-21301",
    "CVE-2022-21302",
    "CVE-2022-21303",
    "CVE-2022-21304",
    "CVE-2022-21339",
    "CVE-2022-21342",
    "CVE-2022-21344",
    "CVE-2022-21348",
    "CVE-2022-21351",
    "CVE-2022-21358",
    "CVE-2022-21362",
    "CVE-2022-21367",
    "CVE-2022-21368",
    "CVE-2022-21370",
    "CVE-2022-21372",
    "CVE-2022-21374",
    "CVE-2022-21378",
    "CVE-2022-21379"
  );
  script_xref(name:"USN", value:"5270-1");
  script_xref(name:"IAVA", value:"2022-A-0030");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : MySQL vulnerabilities (USN-5270-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5270-1 advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Privileges).
    Supported versions that are affected are 5.7.36 and prior and 8.0.27 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of MySQL Server accessible data. CVSS 3.1 Base Score 4.3 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N). (CVE-2022-21245)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    MySQL Server. CVSS 3.1 Base Score 2.7 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L). (CVE-2022-21249)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21253, CVE-2022-21264, CVE-2022-21339,
    CVE-2022-21342, CVE-2022-21370)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.27 and prior. Difficult to exploit vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 5.3 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21254)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Group Replication Plugin).
    Supported versions that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21256, CVE-2022-21379)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of MySQL Server
    accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of MySQL
    Server. CVSS 3.1 Base Score 3.8 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L). (CVE-2022-21265)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Federated). Supported
    versions that are affected are 5.7.36 and prior and 8.0.27 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21270)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2022-21301)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.27 and prior. Difficult to exploit vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 5.3 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21302)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 5.7.36 and prior and 8.0.27 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21303)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Parser). Supported versions
    that are affected are 5.7.36 and prior and 8.0.27 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21304)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
    versions that are affected are 5.7.36 and prior and 8.0.27 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21344)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.27 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21348)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. CVSS 3.1 Base Score 7.1 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H). (CVE-2022-21351)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption).
    Supported versions that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21358)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Information Schema).
    Supported versions that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21362, CVE-2022-21374)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Compiling). Supported
    versions that are affected are 5.7.36 and prior and 8.0.27 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to
    some of MySQL Server accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2022-21367)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Components Services).
    Supported versions that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of MySQL
    Server accessible data as well as unauthorized read access to a subset of MySQL Server accessible data and
    unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Server. CVSS 3.1 Base
    Score 4.7 (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L). (CVE-2022-21368)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption).
    Supported versions that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service
    (partial DOS) of MySQL Server. CVSS 3.1 Base Score 2.7 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L). (CVE-2022-21372)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.27 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2022-21378)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5270-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21368");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21351");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqld-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-router");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-source-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-source-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite-8.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqlclient20', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqld-dev', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client-5.7', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client-core-5.7', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server-5.7', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server-core-5.7', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-source-5.7', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-testsuite', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-testsuite-5.7', 'pkgver': '5.7.37-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.28-0ubuntu0.20.04.3'},
    {'osver': '21.10', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'mysql-client', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'mysql-router', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'mysql-server', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.28-0ubuntu0.21.10.3'},
    {'osver': '21.10', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.28-0ubuntu0.21.10.3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmysqlclient-dev / libmysqlclient20 / libmysqlclient21 / etc');
}
