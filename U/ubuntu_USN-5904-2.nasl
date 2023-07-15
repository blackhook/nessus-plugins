#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5904-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173052);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2021-33844");
  script_xref(name:"USN", value:"5904-2");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : SoX regression (USN-5904-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by
a vulnerability as referenced in the USN-5904-2 advisory.

  - A floating point exception (divide-by-zero) issue was discovered in SoX in functon startread() of wav.c
    file. An attacker with a crafted wav file, could cause an application to crash. (CVE-2021-33844)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5904-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33844");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsox-fmt-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsox-fmt-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsox-fmt-ao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsox-fmt-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsox-fmt-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsox-fmt-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsox-fmt-pulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsox2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsox3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sox");
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
    {'osver': '16.04', 'pkgname': 'libsox-dev', 'pkgver': '14.4.1-5+deb8u4ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'libsox-fmt-all', 'pkgver': '14.4.1-5+deb8u4ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'libsox-fmt-alsa', 'pkgver': '14.4.1-5+deb8u4ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'libsox-fmt-ao', 'pkgver': '14.4.1-5+deb8u4ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'libsox-fmt-base', 'pkgver': '14.4.1-5+deb8u4ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'libsox-fmt-mp3', 'pkgver': '14.4.1-5+deb8u4ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'libsox-fmt-oss', 'pkgver': '14.4.1-5+deb8u4ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'libsox-fmt-pulse', 'pkgver': '14.4.1-5+deb8u4ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'libsox2', 'pkgver': '14.4.1-5+deb8u4ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'sox', 'pkgver': '14.4.1-5+deb8u4ubuntu0.1+esm2'},
    {'osver': '18.04', 'pkgname': 'libsox-dev', 'pkgver': '14.4.2-3ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libsox-fmt-all', 'pkgver': '14.4.2-3ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libsox-fmt-alsa', 'pkgver': '14.4.2-3ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libsox-fmt-ao', 'pkgver': '14.4.2-3ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libsox-fmt-base', 'pkgver': '14.4.2-3ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libsox-fmt-mp3', 'pkgver': '14.4.2-3ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libsox-fmt-oss', 'pkgver': '14.4.2-3ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libsox-fmt-pulse', 'pkgver': '14.4.2-3ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libsox3', 'pkgver': '14.4.2-3ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'sox', 'pkgver': '14.4.2-3ubuntu0.18.04.3'},
    {'osver': '20.04', 'pkgname': 'libsox-dev', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsox-fmt-all', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsox-fmt-alsa', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsox-fmt-ao', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsox-fmt-base', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsox-fmt-mp3', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsox-fmt-oss', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsox-fmt-pulse', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libsox3', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'sox', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'libsox-dev', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsox-fmt-all', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsox-fmt-alsa', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsox-fmt-ao', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsox-fmt-base', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsox-fmt-mp3', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsox-fmt-oss', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsox-fmt-pulse', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libsox3', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'sox', 'pkgver': '14.4.2+git20190427-2+deb11u2build0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'libsox-dev', 'pkgver': '14.4.2+git20190427-3ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libsox-fmt-all', 'pkgver': '14.4.2+git20190427-3ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libsox-fmt-alsa', 'pkgver': '14.4.2+git20190427-3ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libsox-fmt-ao', 'pkgver': '14.4.2+git20190427-3ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libsox-fmt-base', 'pkgver': '14.4.2+git20190427-3ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libsox-fmt-mp3', 'pkgver': '14.4.2+git20190427-3ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libsox-fmt-oss', 'pkgver': '14.4.2+git20190427-3ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libsox-fmt-pulse', 'pkgver': '14.4.2+git20190427-3ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libsox3', 'pkgver': '14.4.2+git20190427-3ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'sox', 'pkgver': '14.4.2+git20190427-3ubuntu0.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsox-dev / libsox-fmt-all / libsox-fmt-alsa / libsox-fmt-ao / etc');
}
