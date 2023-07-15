#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5081-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153446);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-17507", "CVE-2021-38593");
  script_xref(name:"USN", value:"5081-1");

  script_name(english:"Ubuntu 18.04 LTS : Qt vulnerabilities (USN-5081-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5081-1 advisory.

  - An issue was discovered in Qt through 5.12.9, and 5.13.x through 5.15.x before 5.15.1. read_xbm_body in
    gui/image/qxbmhandler.cpp has a buffer over-read. (CVE-2020-17507)

  - Qt 5.0.0 through 6.1.2 has an out-of-bounds write in QOutlineMapper::convertPath (called from
    QRasterPaintEngine::fill and QPaintEngineEx::stroke). (CVE-2021-38593)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5081-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38593");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5core5a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5dbus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5opengl5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5opengl5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5printsupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-ibase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5sql5-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-gtk-platformtheme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-qmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qt5-qmake-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qtbase5-private-dev");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'libqt5concurrent5', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5core5a', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5dbus5', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5gui5', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5network5', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5opengl5', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5opengl5-dev', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5printsupport5', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-ibase', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-mysql', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-odbc', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-psql', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-sqlite', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5sql5-tds', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5test5', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5widgets5', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libqt5xml5', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'qt5-default', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'qt5-gtk-platformtheme', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'qt5-qmake', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'qt5-qmake-bin', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'qtbase5-dev', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'qtbase5-dev-tools', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'qtbase5-examples', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'qtbase5-private-dev', 'pkgver': '5.9.5+dfsg-0ubuntu2.6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libqt5concurrent5 / libqt5core5a / libqt5dbus5 / libqt5gui5 / etc');
}
