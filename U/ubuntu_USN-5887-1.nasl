#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5887-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171930);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/27");

  script_cve_id("CVE-2023-20032", "CVE-2023-20052");
  script_xref(name:"USN", value:"5887-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : ClamAV vulnerabilities (USN-5887-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5887-1 advisory.

  - - Fix daily.cvd file - Split out documentation into separate -doc sub-package - (#2128276) Please port
    your pcre dependency to pcre2 - Explicit dependency on systemd since systemd-devel no longer has this
    dependency on F37+ - (#2136977) not requires data(clamav) on clamav-libs - (#2023371) Add documentation to
    preserve user permissions of DatabaseOwner  ----  ClamAV 0.103.8 is a critical patch release with the
    following fixes:   *   CVE-2023-20032<https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20032>:
    Fixed a possible remote code execution vulnerability in the HFS+ file parser. The issue affects versions
    1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and earlier. Thank you to Simon Scannell for reporting
    this issue.   *   CVE-2023-20052<https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20052>: Fixed a
    possible remote information leak vulnerability in the DMG file parser. The issue affects versions 1.0.0
    and earlier, 0.105.1 and earlier, and 0.103.7 and earlier. Thank you to Simon Scannell for reporting this
    issue.  (CVE-2023-20032, CVE-2023-20052)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5887-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamdscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav9");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'clamav', 'pkgver': '0.103.8+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.8+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.8+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.8+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.8+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.8+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.8+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.8+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '16.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.8+dfsg-0ubuntu0.16.04.1+esm1'},
    {'osver': '18.04', 'pkgname': 'clamav', 'pkgver': '0.103.8+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.8+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.8+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.8+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.8+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.8+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.8+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.8+dfsg-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.8+dfsg-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav', 'pkgver': '0.103.8+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.8+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.8+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.8+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.8+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.8+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.8+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.8+dfsg-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.8+dfsg-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav-base', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav-milter', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'clamdscan', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libclamav9', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'clamav', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'clamav-base', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'clamav-daemon', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'clamav-freshclam', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'clamav-milter', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'clamav-testfiles', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'clamdscan', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libclamav-dev', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libclamav9', 'pkgver': '0.103.8+dfsg-0ubuntu0.22.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clamav / clamav-base / clamav-daemon / clamav-freshclam / etc');
}
