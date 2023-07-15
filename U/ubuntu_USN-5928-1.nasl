#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5928-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172227);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id("CVE-2022-3821", "CVE-2022-4415", "CVE-2022-45873");
  script_xref(name:"USN", value:"5928-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : systemd vulnerabilities (USN-5928-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5928-1 advisory.

  - An off-by-one Error issue was discovered in Systemd in format_timespan() function of time-util.c. An
    attacker could supply specific values for time and accuracy that leads to buffer overrun in
    format_timespan(), leading to a Denial of Service. (CVE-2022-3821)

  - A vulnerability was found in systemd. This security flaw can cause a local information leak due to
    systemd-coredump not respecting the fs.suid_dumpable kernel setting. (CVE-2022-4415)

  - systemd 250 and 251 allows local users to achieve a systemd-coredump deadlock by triggering a crash that
    has a long backtrace. This occurs in parse_elf_object in shared/elf-util.c. The exploitation methodology
    is to crash a binary calling the same function recursively, and put it in a deeply nested directory to
    make its backtrace large enough to cause the deadlock. This must be done 16 times when MaxConnections=16
    is set for the systemd/units/systemd-coredump.socket file. (CVE-2022-45873)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5928-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4415");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-gudev-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgudev-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgudev-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-resolve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-daemon-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-daemon0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-id128-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-id128-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-journal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-journal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-login-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-login0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-boot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-boot-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-homed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-oomd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-repart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-standalone-sysusers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-standalone-tmpfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-timesyncd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-userdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udev");
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
    {'osver': '16.04', 'pkgname': 'libnss-myhostname', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'libnss-mymachines', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'libnss-resolve', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'libpam-systemd', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'libsystemd-dev', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'libsystemd0', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'libudev-dev', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'libudev1', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'systemd', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'systemd-container', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'systemd-coredump', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'systemd-sysv', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '16.04', 'pkgname': 'udev', 'pkgver': '229-4ubuntu21.31+esm3'},
    {'osver': '18.04', 'pkgname': 'libnss-myhostname', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'libnss-mymachines', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'libnss-resolve', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'libnss-systemd', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'libpam-systemd', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'libsystemd-dev', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'libsystemd0', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'libudev-dev', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'libudev1', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'systemd', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'systemd-container', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'systemd-coredump', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'systemd-sysv', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'systemd-tests', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '18.04', 'pkgname': 'udev', 'pkgver': '237-3ubuntu10.57'},
    {'osver': '20.04', 'pkgname': 'libnss-myhostname', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'libnss-mymachines', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'libnss-resolve', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'libnss-systemd', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'libpam-systemd', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'libsystemd-dev', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'libsystemd0', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'libudev-dev', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'libudev1', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'systemd', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'systemd-container', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'systemd-coredump', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'systemd-sysv', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'systemd-tests', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'systemd-timesyncd', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '20.04', 'pkgname': 'udev', 'pkgver': '245.4-4ubuntu3.20'},
    {'osver': '22.04', 'pkgname': 'libnss-myhostname', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libnss-mymachines', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libnss-resolve', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libnss-systemd', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libpam-systemd', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libsystemd-dev', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libsystemd0', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libudev-dev', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'libudev1', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd-container', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd-coredump', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd-oomd', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd-repart', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd-standalone-sysusers', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd-standalone-tmpfiles', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd-sysv', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd-tests', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'systemd-timesyncd', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'udev', 'pkgver': '249.11-0ubuntu3.7'},
    {'osver': '22.10', 'pkgname': 'libnss-myhostname', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'libnss-mymachines', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'libnss-resolve', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'libnss-systemd', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'libpam-systemd', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'libsystemd-dev', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'libsystemd-shared', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'libsystemd0', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'libudev-dev', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'libudev1', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-boot', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-boot-efi', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-container', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-coredump', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-homed', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-journal-remote', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-oomd', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-resolved', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-standalone-sysusers', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-standalone-tmpfiles', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-sysv', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-tests', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-timesyncd', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'systemd-userdbd', 'pkgver': '251.4-1ubuntu7.1'},
    {'osver': '22.10', 'pkgname': 'udev', 'pkgver': '251.4-1ubuntu7.1'}
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
