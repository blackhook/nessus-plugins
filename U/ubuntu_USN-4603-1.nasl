##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4603-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141921);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-2752",
    "CVE-2020-2760",
    "CVE-2020-2812",
    "CVE-2020-2814",
    "CVE-2020-13249",
    "CVE-2020-15180"
  );
  script_xref(name:"USN", value:"4603-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : MariaDB vulnerabilities (USN-4603-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4603-1 advisory.

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.47 and prior, 5.7.27 and prior and 8.0.17 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2752)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.29 and prior and 8.0.19 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server as well as unauthorized update, insert or delete access to some of
    MySQL Server accessible data. CVSS 3.0 Base Score 5.5 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2020-2760)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2812)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.6.47 and prior, 5.7.28 and prior and 8.0.18 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2814)

  - libmariadb/mariadb_lib.c in MariaDB Connector/C before 3.1.8 does not properly validate the content of an
    OK packet received from a server. NOTE: although mariadb_lib.c was originally based on code shipped for
    MySQL, this issue does not affect any MySQL components supported by Oracle. (CVE-2020-13249)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4603-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbclient-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-core-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-connect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-cracklib-password-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-gssapi-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-mroonga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-oqgraph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-rocksdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-spider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-tokudb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-core-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-test-data");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'libmariadbclient-dev', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmariadbclient-dev-compat', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmariadbclient18', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmariadbd-dev', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libmariadbd18', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-client', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-client-10.1', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-client-core-10.1', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-common', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-connect', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-cracklib-password-check', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-gssapi-client', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-gssapi-server', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-mroonga', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-oqgraph', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-spider', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-plugin-tokudb', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-server', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-server-10.1', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-server-core-10.1', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-test', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'mariadb-test-data', 'pkgver': '1:10.1.47-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadb-dev', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadb-dev-compat', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadb3', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadbclient-dev', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadbd-dev', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libmariadbd19', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-backup', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-client', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-client-10.3', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-client-core-10.3', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-common', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-connect', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-cracklib-password-check', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-gssapi-client', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-gssapi-server', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-mroonga', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-oqgraph', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-rocksdb', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-spider', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-plugin-tokudb', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-server', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-server-10.3', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-server-core-10.3', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-test', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'mariadb-test-data', 'pkgver': '1:10.3.25-0ubuntu0.20.04.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmariadb-dev / libmariadb-dev-compat / libmariadb3 / etc');
}