#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5610-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165084);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2022-24713");
  script_xref(name:"USN", value:"5610-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : rust-regex vulnerability (USN-5610-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-5610-1 advisory.

  - regex is an implementation of regular expressions for the Rust language. The regex crate features built-in
    mitigations to prevent denial of service attacks caused by untrusted regexes, or untrusted input matched
    by trusted regexes. Those (tunable) mitigations already provide sane defaults to prevent attacks. This
    guarantee is documented and it's considered part of the crate's API. Unfortunately a bug was discovered in
    the mitigations designed to prevent untrusted regexes to take an arbitrary amount of time during parsing,
    and it's possible to craft regexes that bypass such mitigations. This makes it possible to perform denial
    of service attacks by sending specially crafted regexes to services accepting user-controlled, untrusted
    regexes. All versions of the regex crate before or equal to 1.5.4 are affected by this issue. The fix is
    include starting from regex 1.5.5. All users accepting user-controlled regexes are recommended to upgrade
    immediately to the latest version of the regex crate. Unfortunately there is no fixed set of problematic
    regexes, as there are practically infinite regexes that could be crafted to exploit this vulnerability.
    Because of this, it us not recommend to deny known problematic regexes. (CVE-2022-24713)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5610-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+aho-corasick-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+default-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+memchr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+perf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+perf-literal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+unicode-age-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+unicode-bool-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+unicode-case-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+unicode-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+unicode-gencat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+unicode-perl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+unicode-script-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex+unicode-segment-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librust-regex-dev");
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
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(20\.04|22\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'librust-regex-dev', 'pkgver': '1.2.1-3ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+aho-corasick-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+default-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+memchr-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+perf-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+perf-literal-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+unicode-age-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+unicode-bool-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+unicode-case-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+unicode-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+unicode-gencat-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+unicode-perl-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+unicode-script-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex+unicode-segment-dev', 'pkgver': '1.5.4-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'librust-regex-dev', 'pkgver': '1.5.4-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'librust-regex+aho-corasick-dev / librust-regex+default-dev / etc');
}
