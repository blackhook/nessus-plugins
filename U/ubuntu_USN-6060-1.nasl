#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6060-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175283);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/08");

  script_cve_id(
    "CVE-2023-21911",
    "CVE-2023-21912",
    "CVE-2023-21919",
    "CVE-2023-21920",
    "CVE-2023-21929",
    "CVE-2023-21933",
    "CVE-2023-21935",
    "CVE-2023-21940",
    "CVE-2023-21945",
    "CVE-2023-21946",
    "CVE-2023-21947",
    "CVE-2023-21953",
    "CVE-2023-21955",
    "CVE-2023-21962",
    "CVE-2023-21966",
    "CVE-2023-21972",
    "CVE-2023-21976",
    "CVE-2023-21977",
    "CVE-2023-21980",
    "CVE-2023-21982"
  );
  script_xref(name:"USN", value:"6060-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : MySQL vulnerabilities (USN-6060-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6060-1 advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. (CVE-2023-21911)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Privileges).
    Supported versions that are affected are 5.7.41 and prior and 8.0.30 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2023-21912)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21919, CVE-2023-21933)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21920, CVE-2023-21935, CVE-2023-21945, CVE-2023-21976, CVE-2023-21977,
    CVE-2023-21982)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. (CVE-2023-21929)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Components Services).
    Supported versions that are affected are 8.0.32 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2023-21940, CVE-2023-21947)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21946)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Partition). Supported
    versions that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21953, CVE-2023-21955)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Components Services).
    Supported versions that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2023-21962)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: JSON). Supported versions
    that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21966)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2023-21972)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Client programs). Supported versions
    that are affected are 5.7.41 and prior and 8.0.32 and prior. Difficult to exploit vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks require human interaction from a person other than the attacker. Successful attacks of this
    vulnerability can result in takeover of MySQL Server. (CVE-2023-21980)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6060-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(18\.04|20\.04|22\.04|22\.10|23\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqlclient20', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqld-dev', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client-5.7', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client-core-5.7', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server-5.7', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server-core-5.7', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-source-5.7', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-testsuite', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-testsuite-5.7', 'pkgver': '5.7.42-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.33-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.33-0ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mysql-client', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mysql-router', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mysql-server', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.33-0ubuntu0.22.10.1'},
    {'osver': '23.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.33-0ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.33-0ubuntu0.23.04.1'}
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
    severity   : SECURITY_HOLE,
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
