##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4640-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143214);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-16123");
  script_xref(name:"USN", value:"4640-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : PulseAudio vulnerability (USN-4640-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-4640-1 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4640-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16123");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-mainloop-glib0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulsedsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-equalizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-esound-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-droid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-gconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-gsettings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-lirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-raop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-trust-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-utils");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'libpulse-dev', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'libpulse-mainloop-glib0', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'libpulse0', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'libpulsedsp', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-esound-compat', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-bluetooth', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-droid', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-gconf', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-jack', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-lirc', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-raop', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-trust-store', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-x11', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-zeroconf', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-utils', 'pkgver': '1:8.0-0ubuntu3.15'},
    {'osver': '18.04', 'pkgname': 'libpulse-dev', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'libpulse-mainloop-glib0', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'libpulse0', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'libpulsedsp', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'pulseaudio', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'pulseaudio-equalizer', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'pulseaudio-esound-compat', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'pulseaudio-module-bluetooth', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'pulseaudio-module-gconf', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'pulseaudio-module-jack', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'pulseaudio-module-lirc', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'pulseaudio-module-raop', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'pulseaudio-module-zeroconf', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '18.04', 'pkgname': 'pulseaudio-utils', 'pkgver': '1:11.1-1ubuntu7.11'},
    {'osver': '20.04', 'pkgname': 'libpulse-dev', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'libpulse-mainloop-glib0', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'libpulse0', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'libpulsedsp', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'pulseaudio', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'pulseaudio-equalizer', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'pulseaudio-module-bluetooth', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'pulseaudio-module-gsettings', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'pulseaudio-module-jack', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'pulseaudio-module-lirc', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'pulseaudio-module-raop', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'pulseaudio-module-zeroconf', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.04', 'pkgname': 'pulseaudio-utils', 'pkgver': '1:13.99.1-1ubuntu3.8'},
    {'osver': '20.10', 'pkgname': 'libpulse-dev', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'libpulse-mainloop-glib0', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'libpulse0', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'libpulsedsp', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'pulseaudio', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'pulseaudio-equalizer', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'pulseaudio-module-bluetooth', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'pulseaudio-module-gsettings', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'pulseaudio-module-jack', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'pulseaudio-module-lirc', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'pulseaudio-module-raop', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'pulseaudio-module-zeroconf', 'pkgver': '1:13.99.2-1ubuntu2.1'},
    {'osver': '20.10', 'pkgname': 'pulseaudio-utils', 'pkgver': '1:13.99.2-1ubuntu2.1'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpulse-dev / libpulse-mainloop-glib0 / libpulse0 / libpulsedsp / etc');
}