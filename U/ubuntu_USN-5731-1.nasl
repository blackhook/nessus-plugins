#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5731-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167900);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-41973", "CVE-2022-41974");
  script_xref(name:"USN", value:"5731-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : multipath-tools vulnerabilities (USN-5731-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5731-1 advisory.

  - multipath-tools 0.7.7 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited in
    conjunction with CVE-2022-41974. Local users able to access /dev/shm can change symlinks in multipathd due
    to incorrect symlink handling, which could lead to controlled file writes outside of the /dev/shm
    directory. This could be used indirectly for local privilege escalation to root. (CVE-2022-41973)

  - multipath-tools 0.7.0 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited
    alone or in conjunction with CVE-2022-41973. Local users able to write to UNIX domain sockets can bypass
    access controls and manipulate the multipath setup. This can lead to local privilege escalation to root.
    This occurs because an attacker can repeat a keyword, which is mishandled because arithmetic ADD is used
    instead of bitwise OR. (CVE-2022-41974)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5731-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41974");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpartx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpartx-boot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multipath-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multipath-tools-boot");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'kpartx', 'pkgver': '0.7.4-2ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'kpartx-boot', 'pkgver': '0.7.4-2ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'multipath-tools', 'pkgver': '0.7.4-2ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'multipath-tools-boot', 'pkgver': '0.7.4-2ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'kpartx', 'pkgver': '0.8.3-1ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'kpartx-boot', 'pkgver': '0.8.3-1ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'multipath-tools', 'pkgver': '0.8.3-1ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'multipath-tools-boot', 'pkgver': '0.8.3-1ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'kpartx', 'pkgver': '0.8.8-1ubuntu1.22.04.1'},
    {'osver': '22.04', 'pkgname': 'kpartx-boot', 'pkgver': '0.8.8-1ubuntu1.22.04.1'},
    {'osver': '22.04', 'pkgname': 'multipath-tools', 'pkgver': '0.8.8-1ubuntu1.22.04.1'},
    {'osver': '22.04', 'pkgname': 'multipath-tools-boot', 'pkgver': '0.8.8-1ubuntu1.22.04.1'},
    {'osver': '22.10', 'pkgname': 'kpartx', 'pkgver': '0.8.8-1ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'kpartx-boot', 'pkgver': '0.8.8-1ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'multipath-tools', 'pkgver': '0.8.8-1ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'multipath-tools-boot', 'pkgver': '0.8.8-1ubuntu1.22.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kpartx / kpartx-boot / multipath-tools / multipath-tools-boot');
}
