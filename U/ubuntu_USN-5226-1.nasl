#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5226-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156711);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-3997");
  script_xref(name:"USN", value:"5226-1");

  script_name(english:"Ubuntu 20.04 LTS / 21.04 / 21.10 : systemd vulnerability (USN-5226-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 21.04 / 21.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-5226-1 advisory.

  - A flaw was found in systemd. An uncontrolled recursion in systemd-tmpfiles may lead to a denial of service
    at boot time when too many nested directories are created in /tmp. (CVE-2021-3997)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5226-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3997");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-resolve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-timesyncd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udev");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(20\.04|21\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 21.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '20.04', 'pkgname': 'libnss-myhostname', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'libnss-mymachines', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'libnss-resolve', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'libnss-systemd', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'libpam-systemd', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'libsystemd-dev', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'libsystemd0', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'libudev-dev', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'libudev1', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'systemd', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'systemd-container', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'systemd-coredump', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'systemd-sysv', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'systemd-tests', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'systemd-timesyncd', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '20.04', 'pkgname': 'udev', 'pkgver': '245.4-4ubuntu3.15'},
    {'osver': '21.04', 'pkgname': 'libnss-myhostname', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'libnss-mymachines', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'libnss-resolve', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'libnss-systemd', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'libpam-systemd', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'libsystemd-dev', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'libsystemd0', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'libudev-dev', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'libudev1', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'systemd', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'systemd-container', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'systemd-coredump', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'systemd-sysv', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'systemd-tests', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'systemd-timesyncd', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.04', 'pkgname': 'udev', 'pkgver': '247.3-3ubuntu3.7'},
    {'osver': '21.10', 'pkgname': 'libnss-myhostname', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'libnss-mymachines', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'libnss-resolve', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'libnss-systemd', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'libpam-systemd', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'libsystemd-dev', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'libsystemd0', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'libudev-dev', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'libudev1', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'systemd', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'systemd-container', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'systemd-coredump', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'systemd-journal-remote', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'systemd-sysv', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'systemd-tests', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'systemd-timesyncd', 'pkgver': '248.3-1ubuntu8.2'},
    {'osver': '21.10', 'pkgname': 'udev', 'pkgver': '248.3-1ubuntu8.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss-myhostname / libnss-mymachines / libnss-resolve / etc');
}
