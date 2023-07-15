#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5235-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156802);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-41816", "CVE-2021-41817", "CVE-2021-41819");
  script_xref(name:"USN", value:"5235-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.04 / 21.10 : Ruby vulnerabilities (USN-5235-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.04 / 21.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5235-1 advisory.

  - CGI::Cookie.parse in Ruby through 2.6.8 mishandles security prefixes in cookie names. This also affects
    the CGI gem through 0.3.0 for Ruby. (CVE-2021-41819)

  - CGI.escape_html in Ruby before 2.7.5 and 3.x before 3.0.3 has an integer overflow and resultant buffer
    overflow via a long string on platforms (such as Windows) where size_t and long have different numbers of
    bytes. This also affects the CGI gem before 0.3.1 for Ruby. (CVE-2021-41816)

  - Date.parse in the date gem through 3.2.0 for Ruby allows ReDoS (regular expression Denial of Service) via
    a long string. The fixed versions are 3.2.1, 3.1.2, 3.0.2, and 2.0.1. (CVE-2021-41817)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5235-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.3-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.7-dev");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|21\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 21.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '16.04', 'pkgname': 'libruby2.3', 'pkgver': '2.3.1-2~ubuntu16.04.16+esm2'},
    {'osver': '16.04', 'pkgname': 'ruby2.3', 'pkgver': '2.3.1-2~ubuntu16.04.16+esm2'},
    {'osver': '16.04', 'pkgname': 'ruby2.3-dev', 'pkgver': '2.3.1-2~ubuntu16.04.16+esm2'},
    {'osver': '16.04', 'pkgname': 'ruby2.3-tcltk', 'pkgver': '2.3.1-2~ubuntu16.04.16+esm2'},
    {'osver': '18.04', 'pkgname': 'libruby2.5', 'pkgver': '2.5.1-1ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'ruby2.5', 'pkgver': '2.5.1-1ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'ruby2.5-dev', 'pkgver': '2.5.1-1ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'libruby2.7', 'pkgver': '2.7.0-5ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'ruby2.7', 'pkgver': '2.7.0-5ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'ruby2.7-dev', 'pkgver': '2.7.0-5ubuntu1.6'},
    {'osver': '21.04', 'pkgname': 'libruby2.7', 'pkgver': '2.7.2-4ubuntu1.3'},
    {'osver': '21.04', 'pkgname': 'ruby2.7', 'pkgver': '2.7.2-4ubuntu1.3'},
    {'osver': '21.04', 'pkgname': 'ruby2.7-dev', 'pkgver': '2.7.2-4ubuntu1.3'},
    {'osver': '21.10', 'pkgname': 'libruby2.7', 'pkgver': '2.7.4-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'ruby2.7', 'pkgver': '2.7.4-1ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'ruby2.7-dev', 'pkgver': '2.7.4-1ubuntu3.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libruby2.3 / libruby2.5 / libruby2.7 / ruby2.3 / ruby2.3-dev / etc');
}
