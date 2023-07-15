#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5379-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159882);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-31870",
    "CVE-2021-31871",
    "CVE-2021-31872",
    "CVE-2021-31873"
  );
  script_xref(name:"USN", value:"5379-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS : klibc vulnerabilities (USN-5379-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5379-1 advisory.

  - An issue was discovered in klibc before 2.0.9. Multiplication in the calloc() function may result in an
    integer overflow and a subsequent heap buffer overflow. (CVE-2021-31870)

  - An issue was discovered in klibc before 2.0.9. An integer overflow in the cpio command may result in a
    NULL pointer dereference on 64-bit systems. (CVE-2021-31871)

  - An issue was discovered in klibc before 2.0.9. Multiple possible integer overflows in the cpio command on
    32-bit systems may result in a buffer overflow or other security impact. (CVE-2021-31872)

  - An issue was discovered in klibc before 2.0.9. Additions in the malloc() function may result in an integer
    overflow and a subsequent heap buffer overflow. (CVE-2021-31873)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5379-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected klibc-utils, libklibc and / or libklibc-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:klibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libklibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libklibc-dev");
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
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'klibc-utils', 'pkgver': '2.0.3-0ubuntu1.14.04.3+esm2'},
    {'osver': '14.04', 'pkgname': 'libklibc', 'pkgver': '2.0.3-0ubuntu1.14.04.3+esm2'},
    {'osver': '14.04', 'pkgname': 'libklibc-dev', 'pkgver': '2.0.3-0ubuntu1.14.04.3+esm2'},
    {'osver': '16.04', 'pkgname': 'klibc-utils', 'pkgver': '2.0.4-8ubuntu1.16.04.4+esm1'},
    {'osver': '16.04', 'pkgname': 'libklibc', 'pkgver': '2.0.4-8ubuntu1.16.04.4+esm1'},
    {'osver': '16.04', 'pkgname': 'libklibc-dev', 'pkgver': '2.0.4-8ubuntu1.16.04.4+esm1'},
    {'osver': '18.04', 'pkgname': 'klibc-utils', 'pkgver': '2.0.4-9ubuntu2.1'},
    {'osver': '18.04', 'pkgname': 'libklibc', 'pkgver': '2.0.4-9ubuntu2.1'},
    {'osver': '18.04', 'pkgname': 'libklibc-dev', 'pkgver': '2.0.4-9ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'klibc-utils', 'pkgver': '2.0.7-1ubuntu5.1'},
    {'osver': '20.04', 'pkgname': 'libklibc', 'pkgver': '2.0.7-1ubuntu5.1'},
    {'osver': '20.04', 'pkgname': 'libklibc-dev', 'pkgver': '2.0.7-1ubuntu5.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'klibc-utils / libklibc / libklibc-dev');
}
