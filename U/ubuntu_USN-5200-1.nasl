#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5200-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156171);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-8492", "CVE-2021-3733", "CVE-2021-3737");
  script_xref(name:"USN", value:"5200-1");
  script_xref(name:"IAVA", value:"2020-A-0103-S");
  script_xref(name:"IAVA", value:"2021-A-0497-S");

  script_name(english:"Ubuntu 18.04 LTS : Python vulnerabilities (USN-5200-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5200-1 advisory.

  - Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6 through 3.6.10, 3.7 through 3.7.6, and 3.8 through 3.8.1
    allows an HTTP server to conduct Regular Expression Denial of Service (ReDoS) attacks against a client
    because of urllib.request.AbstractBasicAuthHandler catastrophic backtracking. (CVE-2020-8492)

  - There's a flaw in urllib's AbstractBasicAuthHandler class. An attacker who controls a malicious HTTP
    server that an HTTP client (such as web browser) connects to, could trigger a Regular Expression Denial of
    Service (ReDOS) during an authentication request with a specially crafted payload that is sent by the
    server to the client. The greatest threat that this flaw poses is to application availability.
    (CVE-2021-3733)

  - A flaw was found in python. An improperly handled HTTP response in the HTTP client code of python may
    allow a remote attacker, who controls the HTTP server, to make the client script enter an infinite loop,
    consuming CPU time. The highest threat from this vulnerability is to system availability. (CVE-2021-3737)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5200-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-venv");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'idle-python3.7', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'idle-python3.8', 'pkgver': '3.8.0-3ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.7', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.7-dev', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.7-minimal', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.7-stdlib', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.7-testsuite', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.8', 'pkgver': '3.8.0-3ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.8-dev', 'pkgver': '3.8.0-3ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.8-minimal', 'pkgver': '3.8.0-3ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.8-stdlib', 'pkgver': '3.8.0-3ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.8-testsuite', 'pkgver': '3.8.0-3ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3.7', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3.7-dev', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3.7-examples', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3.7-minimal', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3.7-venv', 'pkgver': '3.7.5-2ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3.8', 'pkgver': '3.8.0-3ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3.8-dev', 'pkgver': '3.8.0-3ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3.8-examples', 'pkgver': '3.8.0-3ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3.8-minimal', 'pkgver': '3.8.0-3ubuntu1~18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3.8-venv', 'pkgver': '3.8.0-3ubuntu1~18.04.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python3.7 / idle-python3.8 / libpython3.7 / libpython3.7-dev / etc');
}
