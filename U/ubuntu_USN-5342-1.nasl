#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5342-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159255);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-3426", "CVE-2021-4189", "CVE-2022-0391");
  script_xref(name:"USN", value:"5342-1");
  script_xref(name:"IAVA", value:"2021-A-0263-S");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS : Python vulnerabilities (USN-5342-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5342-1 advisory.

  - A flaw was found in Python, specifically within the urllib.parse module. This module helps break Uniform
    Resource Locator (URL) strings into components. The issue involves how the urlparse method does not
    sanitize input and allows characters like '\r' and '
' in the URL path. This flaw allows an attacker to
    input a crafted URL, leading to injection attacks. This flaw affects Python versions prior to 3.10.0b1,
    3.9.5, 3.8.11, 3.7.11 and 3.6.14. (CVE-2022-0391)

  - There's a flaw in Python 3's pydoc. A local or adjacent attacker who discovers or is able to convince
    another local or adjacent user to start a pydoc server could access the server and use it to disclose
    sensitive information belonging to the other user that they would not normally be able to access. The
    highest risk of this flaw is to data confidentiality. This flaw affects Python versions before 3.8.9,
    Python versions before 3.9.3 and Python versions before 3.10.0a7. (CVE-2021-3426)

  - A flaw was found in Python, specifically in the FTP (File Transfer Protocol) client library in PASV
    (passive) mode. The issue is how the FTP client trusts the host from the PASV response by default. This
    flaw allows an attacker to set up a malicious FTP server that can trick FTP clients into connecting back
    to a given IP address and port. This vulnerability could lead to FTP client scanning ports, which
    otherwise would not have been possible. (CVE-2021-4189)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5342-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-venv");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(14\.04|16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '14.04', 'pkgname': 'idle-python3.4', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '14.04', 'pkgname': 'libpython3.4', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '14.04', 'pkgname': 'libpython3.4-dev', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '14.04', 'pkgname': 'libpython3.4-minimal', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '14.04', 'pkgname': 'libpython3.4-stdlib', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '14.04', 'pkgname': 'libpython3.4-testsuite', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '14.04', 'pkgname': 'python3.4', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '14.04', 'pkgname': 'python3.4-dev', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '14.04', 'pkgname': 'python3.4-examples', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '14.04', 'pkgname': 'python3.4-minimal', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '14.04', 'pkgname': 'python3.4-venv', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm12'},
    {'osver': '16.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm1'},
    {'osver': '16.04', 'pkgname': 'idle-python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '16.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm1'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm1'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm1'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm1'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm1'},
    {'osver': '16.04', 'pkgname': 'libpython3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-stdlib', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-testsuite', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '16.04', 'pkgname': 'python2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm1'},
    {'osver': '16.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm1'},
    {'osver': '16.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm1'},
    {'osver': '16.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm1'},
    {'osver': '16.04', 'pkgname': 'python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '16.04', 'pkgname': 'python3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '16.04', 'pkgname': 'python3.5-examples', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '16.04', 'pkgname': 'python3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '16.04', 'pkgname': 'python3.5-venv', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm2'},
    {'osver': '18.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'idle-python3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.17-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.17-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.17-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.17-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'libpython3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'libpython3.6-dev', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'libpython3.6-minimal', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'libpython3.6-stdlib', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'libpython3.6-testsuite', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'python2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.17-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.17-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.17-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'python3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'python3.6-dev', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'python3.6-examples', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'python3.6-minimal', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '18.04', 'pkgname': 'python3.6-venv', 'pkgver': '3.6.9-1~18.04ubuntu1.7'},
    {'osver': '20.04', 'pkgname': 'idle-python3.8', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'libpython3.8', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'libpython3.8-dev', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'libpython3.8-minimal', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'libpython3.8-stdlib', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'libpython3.8-testsuite', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'python3.8', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'python3.8-dev', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'python3.8-examples', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'python3.8-full', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'python3.8-minimal', 'pkgver': '3.8.10-0ubuntu1~20.04.4'},
    {'osver': '20.04', 'pkgname': 'python3.8-venv', 'pkgver': '3.8.10-0ubuntu1~20.04.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python2.7 / idle-python3.4 / idle-python3.5 / idle-python3.6 / etc');
}
