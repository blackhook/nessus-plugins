##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5441-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161481);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");
  script_xref(name:"USN", value:"5441-1");

  script_name(english:"Ubuntu 20.04 LTS / 21.10 / 22.04 LTS : WebKitGTK vulnerabilities (USN-5441-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-5441-1 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5441-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-javascriptcoregtk-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-javascriptcoregtk-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-webkit2-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-webkit2-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.0-37-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:webkit2gtk-driver");
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
if (! ('20.04' >< os_release || '21.10' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 21.10 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'gir1.2-javascriptcoregtk-4.0', 'pkgver': '2.36.2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-webkit2-4.0', 'pkgver': '2.36.2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libjavascriptcoregtk-4.0-18', 'pkgver': '2.36.2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libjavascriptcoregtk-4.0-bin', 'pkgver': '2.36.2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libjavascriptcoregtk-4.0-dev', 'pkgver': '2.36.2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwebkit2gtk-4.0-37', 'pkgver': '2.36.2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwebkit2gtk-4.0-37-gtk2', 'pkgver': '2.36.2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwebkit2gtk-4.0-dev', 'pkgver': '2.36.2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'webkit2gtk-driver', 'pkgver': '2.36.2-0ubuntu0.20.04.1'},
    {'osver': '21.10', 'pkgname': 'gir1.2-javascriptcoregtk-4.0', 'pkgver': '2.36.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'gir1.2-webkit2-4.0', 'pkgver': '2.36.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libjavascriptcoregtk-4.0-18', 'pkgver': '2.36.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libjavascriptcoregtk-4.0-bin', 'pkgver': '2.36.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libjavascriptcoregtk-4.0-dev', 'pkgver': '2.36.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libwebkit2gtk-4.0-37', 'pkgver': '2.36.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libwebkit2gtk-4.0-dev', 'pkgver': '2.36.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'webkit2gtk-driver', 'pkgver': '2.36.2-0ubuntu0.21.10.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-javascriptcoregtk-4.0', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-javascriptcoregtk-4.1', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-webkit2-4.0', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-webkit2-4.1', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libjavascriptcoregtk-4.0-18', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libjavascriptcoregtk-4.0-bin', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libjavascriptcoregtk-4.0-dev', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libjavascriptcoregtk-4.1-0', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libjavascriptcoregtk-4.1-dev', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libwebkit2gtk-4.0-37', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libwebkit2gtk-4.0-dev', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libwebkit2gtk-4.1-0', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libwebkit2gtk-4.1-dev', 'pkgver': '2.36.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'webkit2gtk-driver', 'pkgver': '2.36.2-0ubuntu0.22.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-javascriptcoregtk-4.0 / gir1.2-javascriptcoregtk-4.1 / etc');
}
