#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5873-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171575);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id(
    "CVE-2020-14040",
    "CVE-2020-28851",
    "CVE-2020-28852",
    "CVE-2021-38561",
    "CVE-2022-32149"
  );
  script_xref(name:"USN", value:"5873-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Go Text vulnerabilities (USN-5873-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5873-1 advisory.

  - The x/text package before 0.3.3 for Go has a vulnerability in encoding/unicode that could lead to the
    UTF-16 decoder entering an infinite loop, causing the program to crash or run out of memory. An attacker
    could provide a single byte to a UTF16 decoder instantiated with UseBOM or ExpectBOM to trigger an
    infinite loop if the String function on the Decoder is called, or the Decoder is passed to
    golang.org/x/text/transform.String. (CVE-2020-14040)

  - In x/text in Go 1.15.4, an index out of range panic occurs in language.ParseAcceptLanguage while parsing
    the -u- extension. (x/text/language is supposed to be able to parse an HTTP Accept-Language header.)
    (CVE-2020-28851)

  - In x/text in Go before v0.3.5, a slice bounds out of range panic occurs in language.ParseAcceptLanguage
    while processing a BCP 47 tag. (x/text/language is supposed to be able to parse an HTTP Accept-Language
    header.) (CVE-2020-28852)

  - golang.org/x/text/language in golang.org/x/text before 0.3.7 can panic with an out-of-bounds read during
    BCP 47 language tag parsing. Index calculation is mishandled. If parsing untrusted user input, this can be
    used as a vector for a denial-of-service attack. (CVE-2021-38561)

  - An attacker may cause a denial of service by crafting an Accept-Language header which ParseAcceptLanguage
    will take significant time to parse. (CVE-2022-32149)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5873-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-golang-x-text-dev and / or golang-x-text-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28852");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32149");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-golang-x-text-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-x-text-dev");
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
if (! preg(pattern:"^(18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'golang-golang-x-text-dev', 'pkgver': '0.0~git20170627.0.6353ef0-1ubuntu2.1'},
    {'osver': '18.04', 'pkgname': 'golang-x-text-dev', 'pkgver': '0.0~git20170627.0.6353ef0-1ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'golang-golang-x-text-dev', 'pkgver': '0.3.2-4ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'golang-golang-x-text-dev', 'pkgver': '0.3.7-1ubuntu0.20.04.1'},
    {'osver': '22.10', 'pkgname': 'golang-golang-x-text-dev', 'pkgver': '0.3.7-1ubuntu0.22.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-golang-x-text-dev / golang-x-text-dev');
}
