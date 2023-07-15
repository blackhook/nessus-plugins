#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5607-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165011);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-44648");
  script_xref(name:"USN", value:"5607-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : GDK-PixBuf vulnerability (USN-5607-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-5607-1 advisory.

  - GNOME gdk-pixbuf 2.42.6 is vulnerable to a heap-buffer overflow vulnerability when decoding the lzw
    compressed stream of image data in GIF files with lzw minimum code size equals to 12. (CVE-2021-44648)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5607-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44648");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gdk-pixbuf-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-gdkpixbuf-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf-2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf2.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf2.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf2.0-dev");
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
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(20\.04|22\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'gir1.2-gdkpixbuf-2.0', 'pkgver': '2.40.0+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libgdk-pixbuf2.0-0', 'pkgver': '2.40.0+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libgdk-pixbuf2.0-bin', 'pkgver': '2.40.0+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libgdk-pixbuf2.0-common', 'pkgver': '2.40.0+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libgdk-pixbuf2.0-dev', 'pkgver': '2.40.0+dfsg-3ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'gdk-pixbuf-tests', 'pkgver': '2.42.8+dfsg-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-gdkpixbuf-2.0', 'pkgver': '2.42.8+dfsg-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libgdk-pixbuf-2.0-0', 'pkgver': '2.42.8+dfsg-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libgdk-pixbuf-2.0-dev', 'pkgver': '2.42.8+dfsg-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libgdk-pixbuf2.0-bin', 'pkgver': '2.42.8+dfsg-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libgdk-pixbuf2.0-common', 'pkgver': '2.42.8+dfsg-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gdk-pixbuf-tests / gir1.2-gdkpixbuf-2.0 / libgdk-pixbuf-2.0-0 / etc');
}
