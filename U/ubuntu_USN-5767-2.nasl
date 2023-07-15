#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5767-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168534);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-45061");
  script_xref(name:"USN", value:"5767-2");
  script_xref(name:"IAVA", value:"2023-A-0061-S");

  script_name(english:"Ubuntu 16.04 ESM : Python vulnerability (USN-5767-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by a vulnerability as referenced in the
USN-5767-2 advisory.

  - An issue was discovered in Python before 3.11.1. An unnecessary quadratic algorithm exists in one path
    when processing some inputs to the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name
    being presented to the decoder could lead to a CPU denial of service. Hostnames are often supplied by
    remote servers that could be controlled by a malicious actor; in such a scenario, they could trigger
    excessive CPU consumption on the client attempting to make use of an attacker-supplied supposed hostname.
    For example, the attack payload could be placed in the Location header of an HTTP response with status
    code 302. A fix is planned in 3.11.1, 3.10.9, 3.9.16, 3.8.16, and 3.7.16. (CVE-2022-45061)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5767-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45061");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-venv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm3'},
    {'osver': '16.04', 'pkgname': 'idle-python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'},
    {'osver': '16.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm3'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm3'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm3'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm3'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm3'},
    {'osver': '16.04', 'pkgname': 'libpython3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-stdlib', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-testsuite', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'},
    {'osver': '16.04', 'pkgname': 'python2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm3'},
    {'osver': '16.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm3'},
    {'osver': '16.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm3'},
    {'osver': '16.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm3'},
    {'osver': '16.04', 'pkgname': 'python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'},
    {'osver': '16.04', 'pkgname': 'python3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'},
    {'osver': '16.04', 'pkgname': 'python3.5-examples', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'},
    {'osver': '16.04', 'pkgname': 'python3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'},
    {'osver': '16.04', 'pkgname': 'python3.5-venv', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm6'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python2.7 / idle-python3.5 / libpython2.7 / libpython2.7-dev / etc');
}
