#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5966-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173253);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2022-37703", "CVE-2022-37704", "CVE-2022-37705");
  script_xref(name:"USN", value:"5966-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : amanda vulnerabilities (USN-5966-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-5966-1 advisory.

  - In Amanda 3.5.1, an information leak vulnerability was found in the calcsize SUID binary. An attacker can
    abuse this vulnerability to know if a directory exists or not anywhere in the fs. The binary will use
    `opendir()` as root directly without checking the path, letting the attacker provide an arbitrary path.
    (CVE-2022-37703)

  - Amanda 3.5.1 allows privilege escalation from the regular user backup to root. The SUID binary located at
    /lib/amanda/rundump will execute /usr/sbin/dump as root with controlled arguments from the attacker which
    may lead to escalation of privileges, denial of service, and information disclosure. (CVE-2022-37704)

  - A privilege escalation flaw was found in Amanda 3.5.1 in which the backup user can acquire root
    privileges. The vulnerable component is the runtar SUID program, which is a wrapper to run /usr/bin/tar
    with specific arguments that are controllable by the attacker. This program mishandles the arguments
    passed to tar binary (it expects that the argument name and value are separated with a space; however,
    separating them with an equals sign is also supported), (CVE-2022-37705)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5966-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected amanda-client, amanda-common and / or amanda-server packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37705");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:amanda-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:amanda-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:amanda-server");
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
if (! preg(pattern:"^(14\.04|16\.04|18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'amanda-client', 'pkgver': '1:3.3.3-2ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'amanda-common', 'pkgver': '1:3.3.3-2ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'amanda-server', 'pkgver': '1:3.3.3-2ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'amanda-client', 'pkgver': '1:3.3.6-4.1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'amanda-common', 'pkgver': '1:3.3.6-4.1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'amanda-server', 'pkgver': '1:3.3.6-4.1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'amanda-client', 'pkgver': '1:3.5.1-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'amanda-common', 'pkgver': '1:3.5.1-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'amanda-server', 'pkgver': '1:3.5.1-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'amanda-client', 'pkgver': '1:3.5.1-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'amanda-common', 'pkgver': '1:3.5.1-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'amanda-server', 'pkgver': '1:3.5.1-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'amanda-client', 'pkgver': '1:3.5.1-8ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'amanda-common', 'pkgver': '1:3.5.1-8ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'amanda-server', 'pkgver': '1:3.5.1-8ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'amanda-client', 'pkgver': '1:3.5.1-9ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'amanda-common', 'pkgver': '1:3.5.1-9ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'amanda-server', 'pkgver': '1:3.5.1-9ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'amanda-client / amanda-common / amanda-server');
}
