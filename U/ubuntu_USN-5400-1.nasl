##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5400-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160474);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-21412",
    "CVE-2022-21413",
    "CVE-2022-21414",
    "CVE-2022-21415",
    "CVE-2022-21417",
    "CVE-2022-21418",
    "CVE-2022-21423",
    "CVE-2022-21425",
    "CVE-2022-21427",
    "CVE-2022-21435",
    "CVE-2022-21436",
    "CVE-2022-21437",
    "CVE-2022-21438",
    "CVE-2022-21440",
    "CVE-2022-21444",
    "CVE-2022-21451",
    "CVE-2022-21452",
    "CVE-2022-21454",
    "CVE-2022-21457",
    "CVE-2022-21459",
    "CVE-2022-21460",
    "CVE-2022-21462",
    "CVE-2022-21478"
  );
  script_xref(name:"USN", value:"5400-1");
  script_xref(name:"IAVA", value:"2022-A-0168-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : MySQL vulnerabilities (USN-5400-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5400-1 advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.28 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21412, CVE-2022-21414, CVE-2022-21435,
    CVE-2022-21436, CVE-2022-21437, CVE-2022-21438, CVE-2022-21452, CVE-2022-21462)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 8.0.28 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21413)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Replication). Supported
    versions that are affected are 8.0.28 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21415)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.37 and prior and 8.0.28 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21417)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.28 and prior. Difficult to exploit vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server as well as unauthorized update, insert or delete access to some of MySQL Server accessible data.
    CVSS 3.1 Base Score 5.0 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2022-21418)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 8.0.28 and prior. Easily exploitable vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Server.
    CVSS 3.1 Base Score 2.7 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L). (CVE-2022-21423)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 8.0.28 and prior. Easily exploitable vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2022-21425)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions
    that are affected are 5.7.37 and prior and 8.0.28 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21427)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 8.0.28 and prior. Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of MySQL Server
    accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2022-21440, CVE-2022-21459, CVE-2022-21478)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions
    that are affected are 5.7.37 and prior and 8.0.28 and prior. Difficult to exploit vulnerability allows
    high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21444)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.37 and prior and 8.0.28 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21451)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Group Replication Plugin).
    Supported versions that are affected are 5.7.37 and prior and 8.0.28 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21454)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: PAM Auth Plugin). Supported
    versions that are affected are 8.0.28 and prior. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized access to critical data or complete access to all MySQL Server
    accessible data. CVSS 3.1 Base Score 5.9 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N). (CVE-2022-21457)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Logging). Supported versions
    that are affected are 5.7.37 and prior and 8.0.28 and prior. Difficult to exploit vulnerability allows
    high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized access to critical data or complete access to all
    MySQL Server accessible data. CVSS 3.1 Base Score 4.4 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N). (CVE-2022-21460)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5400-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21478");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21457");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqlclient20', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmysqld-dev', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client-5.7', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-client-core-5.7', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server-5.7', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-server-core-5.7', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-source-5.7', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-testsuite', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mysql-testsuite-5.7', 'pkgver': '5.7.38-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.29-0ubuntu0.20.04.2'},
    {'osver': '21.10', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'mysql-client', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'mysql-router', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'mysql-server', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.29-0ubuntu0.21.10.1'},
    {'osver': '22.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libmysqlclient21', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-client', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-client-8.0', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-client-core-8.0', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-router', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-server', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-server-8.0', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-server-core-8.0', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-source-8.0', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-testsuite', 'pkgver': '8.0.29-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'mysql-testsuite-8.0', 'pkgver': '8.0.29-0ubuntu0.22.04.1'}
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
