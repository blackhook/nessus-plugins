#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5191-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156055);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-41133");
  script_xref(name:"USN", value:"5191-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.04 / 21.10 : Flatpak vulnerability (USN-5191-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.04 / 21.10 host has packages installed that are affected by a vulnerability
as referenced in the USN-5191-1 advisory.

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. In
    versions prior to 1.10.4 and 1.12.0, Flatpak apps with direct access to AF_UNIX sockets such as those used
    by Wayland, Pipewire or pipewire-pulse can trick portals and other host-OS services into treating the
    Flatpak app as though it was an ordinary, non-sandboxed host-OS process. They can do this by manipulating
    the VFS using recent mount-related syscalls that are not blocked by Flatpak's denylist seccomp filter, in
    order to substitute a crafted `/.flatpak-info` or make that file disappear entirely. Flatpak apps that act
    as clients for AF_UNIX sockets such as those used by Wayland, Pipewire or pipewire-pulse can escalate the
    privileges that the corresponding services will believe the Flatpak app has. Note that protocols that
    operate entirely over the D-Bus session bus (user bus), system bus or accessibility bus are not affected
    by this. This is due to the use of a proxy process `xdg-dbus-proxy`, whose VFS cannot be manipulated by
    the Flatpak app, when interacting with these buses. Patches exist for versions 1.10.4 and 1.12.0, and as
    of time of publication, a patch for version 1.8.2 is being planned. There are no workarounds aside from
    upgrading to a patched version. (CVE-2021-41133)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5191-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:flatpak-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-flatpak-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflatpak-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflatpak0");
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
if (! preg(pattern:"^(18\.04|20\.04|21\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'flatpak', 'pkgver': '1.0.9-0ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'flatpak-tests', 'pkgver': '1.0.9-0ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'gir1.2-flatpak-1.0', 'pkgver': '1.0.9-0ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libflatpak-dev', 'pkgver': '1.0.9-0ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libflatpak0', 'pkgver': '1.0.9-0ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'flatpak', 'pkgver': '1.6.5-0ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'flatpak-tests', 'pkgver': '1.6.5-0ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'gir1.2-flatpak-1.0', 'pkgver': '1.6.5-0ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libflatpak-dev', 'pkgver': '1.6.5-0ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libflatpak0', 'pkgver': '1.6.5-0ubuntu0.4'},
    {'osver': '21.04', 'pkgname': 'flatpak', 'pkgver': '1.10.2-1ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'flatpak-tests', 'pkgver': '1.10.2-1ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'gir1.2-flatpak-1.0', 'pkgver': '1.10.2-1ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'libflatpak-dev', 'pkgver': '1.10.2-1ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'libflatpak0', 'pkgver': '1.10.2-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'flatpak', 'pkgver': '1.10.2-3ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'flatpak-tests', 'pkgver': '1.10.2-3ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'gir1.2-flatpak-1.0', 'pkgver': '1.10.2-3ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libflatpak-dev', 'pkgver': '1.10.2-3ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libflatpak0', 'pkgver': '1.10.2-3ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'flatpak / flatpak-tests / gir1.2-flatpak-1.0 / libflatpak-dev / etc');
}
