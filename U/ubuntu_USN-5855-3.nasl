#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5855-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173780);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/03");
  script_xref(name:"USN", value:"5855-3");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 : ImageMagick regression (USN-5855-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-5855-3 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5855-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16hdri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-q16hdri-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
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
if (! preg(pattern:"^(20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '20.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.7'},
    {'osver': '22.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3'},
    {'osver': '22.10', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'},
    {'osver': '22.10', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'imagemagick / imagemagick-6-common / imagemagick-6.q16 / etc');
}
