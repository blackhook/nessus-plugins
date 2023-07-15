##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5704-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166619);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-42010", "CVE-2022-42011", "CVE-2022-42012");
  script_xref(name:"USN", value:"5704-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : DBus vulnerabilities (USN-5704-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5704-1 advisory.

  - An issue was discovered in D-Bus before 1.12.24, 1.13.x and 1.14.x before 1.14.4, and 1.15.x before
    1.15.2. An authenticated attacker can cause dbus-daemon and other programs that use libdbus to crash when
    receiving a message with certain invalid type signatures. (CVE-2022-42010)

  - An issue was discovered in D-Bus before 1.12.24, 1.13.x and 1.14.x before 1.14.4, and 1.15.x before
    1.15.2. An authenticated attacker can cause dbus-daemon and other programs that use libdbus to crash when
    receiving a message where an array length is inconsistent with the size of the element type.
    (CVE-2022-42011)

  - An issue was discovered in D-Bus before 1.12.24, 1.13.x and 1.14.x before 1.14.4, and 1.15.x before
    1.15.2. An authenticated attacker can cause dbus-daemon and other programs that use libdbus to crash by
    sending a message with attached file descriptors in an unexpected format. (CVE-2022-42012)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5704-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-session-bus-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-system-bus-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-user-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'dbus', 'pkgver': '1.10.6-1ubuntu3.6+esm2'},
    {'osver': '16.04', 'pkgname': 'dbus-tests', 'pkgver': '1.10.6-1ubuntu3.6+esm2'},
    {'osver': '16.04', 'pkgname': 'dbus-user-session', 'pkgver': '1.10.6-1ubuntu3.6+esm2'},
    {'osver': '16.04', 'pkgname': 'dbus-x11', 'pkgver': '1.10.6-1ubuntu3.6+esm2'},
    {'osver': '16.04', 'pkgname': 'libdbus-1-3', 'pkgver': '1.10.6-1ubuntu3.6+esm2'},
    {'osver': '16.04', 'pkgname': 'libdbus-1-dev', 'pkgver': '1.10.6-1ubuntu3.6+esm2'},
    {'osver': '18.04', 'pkgname': 'dbus', 'pkgver': '1.12.2-1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'dbus-tests', 'pkgver': '1.12.2-1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'dbus-user-session', 'pkgver': '1.12.2-1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'dbus-x11', 'pkgver': '1.12.2-1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libdbus-1-3', 'pkgver': '1.12.2-1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libdbus-1-dev', 'pkgver': '1.12.2-1ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'dbus', 'pkgver': '1.12.16-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'dbus-tests', 'pkgver': '1.12.16-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'dbus-user-session', 'pkgver': '1.12.16-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'dbus-x11', 'pkgver': '1.12.16-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libdbus-1-3', 'pkgver': '1.12.16-2ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libdbus-1-dev', 'pkgver': '1.12.16-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'dbus', 'pkgver': '1.12.20-2ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'dbus-tests', 'pkgver': '1.12.20-2ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'dbus-user-session', 'pkgver': '1.12.20-2ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'dbus-x11', 'pkgver': '1.12.20-2ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'libdbus-1-3', 'pkgver': '1.12.20-2ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'libdbus-1-dev', 'pkgver': '1.12.20-2ubuntu4.1'},
    {'osver': '22.10', 'pkgname': 'dbus', 'pkgver': '1.14.0-2ubuntu3'},
    {'osver': '22.10', 'pkgname': 'dbus-bin', 'pkgver': '1.14.0-2ubuntu3'},
    {'osver': '22.10', 'pkgname': 'dbus-daemon', 'pkgver': '1.14.0-2ubuntu3'},
    {'osver': '22.10', 'pkgname': 'dbus-session-bus-common', 'pkgver': '1.14.0-2ubuntu3'},
    {'osver': '22.10', 'pkgname': 'dbus-system-bus-common', 'pkgver': '1.14.0-2ubuntu3'},
    {'osver': '22.10', 'pkgname': 'dbus-tests', 'pkgver': '1.14.0-2ubuntu3'},
    {'osver': '22.10', 'pkgname': 'dbus-user-session', 'pkgver': '1.14.0-2ubuntu3'},
    {'osver': '22.10', 'pkgname': 'dbus-x11', 'pkgver': '1.14.0-2ubuntu3'},
    {'osver': '22.10', 'pkgname': 'libdbus-1-3', 'pkgver': '1.14.0-2ubuntu3'},
    {'osver': '22.10', 'pkgname': 'libdbus-1-dev', 'pkgver': '1.14.0-2ubuntu3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dbus / dbus-bin / dbus-daemon / dbus-session-bus-common / etc');
}
