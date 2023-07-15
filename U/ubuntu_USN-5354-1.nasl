#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5354-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159346);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2022-21712", "CVE-2022-21716");
  script_xref(name:"USN", value:"5354-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : Twisted vulnerabilities (USN-5354-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5354-1 advisory.

  - twisted is an event-driven networking engine written in Python. In affected versions twisted exposes
    cookies and authorization headers when following cross-origin redirects. This issue is present in the
    `twited.web.RedirectAgent` and `twisted.web. BrowserLikeRedirectAgent` functions. Users are advised to
    upgrade. There are no known workarounds. (CVE-2022-21712)

  - Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 22.2.0,
    Twisted SSH client and server implement is able to accept an infinite amount of data for the peer's SSH
    version identifier. This ends up with a buffer using all the available memory. The attach is a simple as
    `nc -rv localhost 22 < /dev/zero`. A patch is available in version 22.2.0. There are currently no known
    workarounds. (CVE-2022-21716)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5354-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-conch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-names");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-words");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-twisted-bin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'python-twisted', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python-twisted-bin', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python-twisted-conch', 'pkgver': '1:17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python-twisted-core', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python-twisted-mail', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python-twisted-names', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python-twisted-news', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python-twisted-runner', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python-twisted-web', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python-twisted-words', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python3-twisted', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '18.04', 'pkgname': 'python3-twisted-bin', 'pkgver': '17.9.0-2ubuntu0.3'},
    {'osver': '20.04', 'pkgname': 'python3-twisted', 'pkgver': '18.9.0-11ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'python3-twisted-bin', 'pkgver': '18.9.0-11ubuntu0.20.04.2'},
    {'osver': '21.10', 'pkgname': 'python3-twisted', 'pkgver': '20.3.0-7ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'python3-twisted-bin', 'pkgver': '20.3.0-7ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-twisted / python-twisted-bin / python-twisted-conch / etc');
}
