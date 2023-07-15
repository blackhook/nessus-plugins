#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5389-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160213);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2017-7960",
    "CVE-2017-8834",
    "CVE-2017-8871",
    "CVE-2020-12825"
  );
  script_xref(name:"USN", value:"5389-1");

  script_name(english:"Ubuntu 16.04 LTS : Libcroco vulnerabilities (USN-5389-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5389-1 advisory.

  - The cr_input_new_from_uri function in cr-input.c in libcroco 0.6.11 and 0.6.12 allows remote attackers to
    cause a denial of service (heap-based buffer over-read) via a crafted CSS file. (CVE-2017-7960)

  - The cr_tknzr_parse_comment function in cr-tknzr.c in libcroco 0.6.12 allows remote attackers to cause a
    denial of service (memory allocation error) via a crafted CSS file. (CVE-2017-8834)

  - The cr_parser_parse_selector_core function in cr-parser.c in libcroco 0.6.12 allows remote attackers to
    cause a denial of service (infinite loop and CPU consumption) via a crafted CSS file. (CVE-2017-8871)

  - libcroco through 0.6.13 has excessive recursion in cr_parser_parse_any_core in cr-parser.c, leading to
    stack consumption. (CVE-2020-12825)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5389-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libcroco-tools, libcroco3 and / or libcroco3-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12825");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcroco-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcroco3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcroco3-dev");
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
    {'osver': '16.04', 'pkgname': 'libcroco-tools', 'pkgver': '0.6.11-1ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libcroco3', 'pkgver': '0.6.11-1ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libcroco3-dev', 'pkgver': '0.6.11-1ubuntu0.1~esm1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcroco-tools / libcroco3 / libcroco3-dev');
}
