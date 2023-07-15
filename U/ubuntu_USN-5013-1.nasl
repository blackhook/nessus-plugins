#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5013-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151836);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-13529", "CVE-2021-33910");
  script_xref(name:"USN", value:"5013-1");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : systemd vulnerabilities (USN-5013-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5013-1 advisory.

  - An exploitable denial-of-service vulnerability exists in Systemd 245. A specially crafted DHCP FORCERENEW
    packet can cause a server running the DHCP client to be vulnerable to a DHCP ACK spoofing attack. An
    attacker can forge a pair of FORCERENEW and DCHP ACK packets to reconfigure the server. (CVE-2020-13529)

  - basic/unit-name.c in systemd 220 through 248 has a Memory Allocation with an Excessive Size Value
    (involving strdupa and alloca for a pathname controlled by a local attacker) that results in an operating
    system crash. (CVE-2021-33910)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5013-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33910");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13529");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-resolve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-timesyncd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udev-udeb");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|20\.10|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'libnss-myhostname', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'libnss-mymachines', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'libnss-resolve', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'libnss-systemd', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'libpam-systemd', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'libsystemd-dev', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'libsystemd0', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'libudev-dev', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'libudev1', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'libudev1-udeb', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'systemd', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'systemd-container', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'systemd-coredump', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'systemd-sysv', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'systemd-tests', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'udev', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '18.04', 'pkgname': 'udev-udeb', 'pkgver': '237-3ubuntu10.49'},
    {'osver': '20.04', 'pkgname': 'libnss-myhostname', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libnss-mymachines', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libnss-resolve', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libnss-systemd', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libpam-systemd', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libsystemd-dev', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libsystemd0', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libudev-dev', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libudev1', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libudev1-udeb', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'systemd', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'systemd-container', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'systemd-coredump', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'systemd-sysv', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'systemd-tests', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'systemd-timesyncd', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'udev', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'udev-udeb', 'pkgver': '245.4-4ubuntu3.10'},
    {'osver': '20.10', 'pkgname': 'libnss-myhostname', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'libnss-mymachines', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'libnss-resolve', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'libnss-systemd', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'libpam-systemd', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'libsystemd-dev', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'libsystemd0', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'libudev-dev', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'libudev1', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'libudev1-udeb', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'systemd', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'systemd-container', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'systemd-coredump', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'systemd-journal-remote', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'systemd-sysv', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'systemd-tests', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'systemd-timesyncd', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'udev', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '20.10', 'pkgname': 'udev-udeb', 'pkgver': '246.6-1ubuntu1.7'},
    {'osver': '21.04', 'pkgname': 'libnss-myhostname', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'libnss-mymachines', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'libnss-resolve', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'libnss-systemd', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'libpam-systemd', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'libsystemd-dev', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'libsystemd0', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'libudev-dev', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'libudev1', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'systemd', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'systemd-container', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'systemd-coredump', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'systemd-sysv', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'systemd-tests', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'systemd-timesyncd', 'pkgver': '247.3-3ubuntu3.4'},
    {'osver': '21.04', 'pkgname': 'udev', 'pkgver': '247.3-3ubuntu3.4'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss-myhostname / libnss-mymachines / libnss-resolve / etc');
}
