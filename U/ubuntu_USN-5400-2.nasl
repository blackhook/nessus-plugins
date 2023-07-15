##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5400-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160507);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-21417",
    "CVE-2022-21427",
    "CVE-2022-21444",
    "CVE-2022-21451",
    "CVE-2022-21454",
    "CVE-2022-21460"
  );
  script_xref(name:"USN", value:"5400-2");
  script_xref(name:"IAVA", value:"2022-A-0168-S");

  script_name(english:"Ubuntu 16.04 LTS : MySQL vulnerabilities (USN-5400-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5400-2 advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.37 and prior and 8.0.28 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21417)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions
    that are affected are 5.7.37 and prior and 8.0.28 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21427)

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

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Logging). Supported versions
    that are affected are 5.7.37 and prior and 8.0.28 and prior. Difficult to exploit vulnerability allows
    high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized access to critical data or complete access to all
    MySQL Server accessible data. CVSS 3.1 Base Score 4.4 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N). (CVE-2022-21460)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5400-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21460");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqld-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client-core-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-core-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-source-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-testsuite-5.7");
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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libmysqlclient-dev', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'libmysqlclient20', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'libmysqld-dev', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'mysql-client', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'mysql-client-5.7', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'mysql-client-core-5.7', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'mysql-common', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'mysql-server', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'mysql-server-5.7', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'mysql-server-core-5.7', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'mysql-source-5.7', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'mysql-testsuite', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'mysql-testsuite-5.7', 'pkgver': '5.7.38-0ubuntu0.16.04.1+esm1'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmysqlclient-dev / libmysqlclient20 / libmysqld-dev / etc');
}
