##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5454-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161723);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2019-8842", "CVE-2020-10001", "CVE-2022-26691");
  script_xref(name:"USN", value:"5454-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : CUPS vulnerabilities (USN-5454-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5454-1 advisory.

  - A buffer overflow was addressed with improved bounds checking. This issue is fixed in macOS Catalina
    10.15.2, Security Update 2019-002 Mojave, and Security Update 2019-007 High Sierra. In certain
    configurations, a remote attacker may be able to submit arbitrary print jobs. (CVE-2019-8842)

  - An input validation issue was addressed with improved memory handling. This issue is fixed in macOS Big
    Sur 11.1, Security Update 2020-001 Catalina, Security Update 2020-007 Mojave. A malicious application may
    be able to read restricted memory. (CVE-2020-10001)

  - A logic issue was addressed with improved state management. This issue is fixed in Security Update
    2022-003 Catalina, macOS Monterey 12.3, macOS Big Sur 11.6.5. An application may be able to gain elevated
    privileges. (CVE-2022-26691)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5454-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26691");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-core-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-ipp-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-ppdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcups2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsppdc1");
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
    {'osver': '18.04', 'pkgname': 'cups', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'cups-bsd', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'cups-client', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'cups-common', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'cups-core-drivers', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'cups-daemon', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'cups-ipp-utils', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'cups-ppdc', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'cups-server-common', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libcups2', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libcups2-dev', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libcupscgi1', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libcupsimage2', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libcupsimage2-dev', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libcupsmime1', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libcupsppdc1', 'pkgver': '2.2.7-1ubuntu2.9'},
    {'osver': '20.04', 'pkgname': 'cups', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'cups-bsd', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'cups-client', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'cups-common', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'cups-core-drivers', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'cups-daemon', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'cups-ipp-utils', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'cups-ppdc', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'cups-server-common', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libcups2', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libcups2-dev', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libcupsimage2', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libcupsimage2-dev', 'pkgver': '2.3.1-9ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'cups', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'cups-bsd', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'cups-client', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'cups-common', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'cups-core-drivers', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'cups-daemon', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'cups-ipp-utils', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'cups-ppdc', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'cups-server-common', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'libcups2', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'libcups2-dev', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'libcupsimage2', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'libcupsimage2-dev', 'pkgver': '2.3.3op2-7ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'cups', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'cups-bsd', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'cups-client', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'cups-common', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'cups-core-drivers', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'cups-daemon', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'cups-ipp-utils', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'cups-ppdc', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'cups-server-common', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'libcups2', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'libcups2-dev', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'libcupsimage2', 'pkgver': '2.4.1op1-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'libcupsimage2-dev', 'pkgver': '2.4.1op1-1ubuntu4.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cups / cups-bsd / cups-client / cups-common / cups-core-drivers / etc');
}
