#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5947-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172497);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/13");

  script_cve_id("CVE-2019-9942", "CVE-2022-23614", "CVE-2022-39261");
  script_xref(name:"USN", value:"5947-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM : Twig vulnerabilities (USN-5947-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5947-1 advisory.

  - A sandbox information disclosure exists in Twig before 1.38.0 and 2.x before 2.7.0 because, under some
    circumstances, it is possible to call the __toString() method on an object even if not allowed by the
    security policy in place. (CVE-2019-9942)

  - Twig is an open source template language for PHP. When in a sandbox mode, the `arrow` parameter of the
    `sort` filter must be a closure to avoid attackers being able to run arbitrary PHP functions. In affected
    versions this constraint was not properly enforced and could lead to code injection of arbitrary PHP code.
    Patched versions now disallow calling non Closure in the `sort` filter as is the case for some other
    filters. Users are advised to upgrade. (CVE-2022-23614)

  - Twig is a template language for PHP. Versions 1.x prior to 1.44.7, 2.x prior to 2.15.3, and 3.x prior to
    3.4.3 encounter an issue when the filesystem loader loads templates for which the name is a user input. It
    is possible to use the `source` or `include` statement to read arbitrary files from outside the templates'
    directory when using a namespace like `@somewhere/../some.file`. In such a case, validation is bypassed.
    Versions 1.44.7, 2.15.3, and 3.4.3 contain a fix for validation of such template names. There are no known
    workarounds aside from upgrading. (CVE-2022-39261)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5947-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-twig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-twig-cache-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-twig-cssinliner-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-twig-extra-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-twig-html-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-twig-inky-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-twig-intl-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-twig-markdown-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-twig-string-extra");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'php-twig', 'pkgver': '1.23.1-1ubuntu4+esm1'},
    {'osver': '18.04', 'pkgname': 'php-twig', 'pkgver': '2.4.6-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'php-twig', 'pkgver': '2.12.5-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'php-twig-cssinliner-extra', 'pkgver': '2.12.5-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'php-twig-extra-bundle', 'pkgver': '2.12.5-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'php-twig-html-extra', 'pkgver': '2.12.5-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'php-twig-inky-extra', 'pkgver': '2.12.5-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'php-twig-intl-extra', 'pkgver': '2.12.5-1ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'php-twig-markdown-extra', 'pkgver': '2.12.5-1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'php-twig', 'pkgver': '3.3.8-2ubuntu4+esm1'},
    {'osver': '22.04', 'pkgname': 'php-twig-cache-extra', 'pkgver': '3.3.8-2ubuntu4+esm1'},
    {'osver': '22.04', 'pkgname': 'php-twig-cssinliner-extra', 'pkgver': '3.3.8-2ubuntu4+esm1'},
    {'osver': '22.04', 'pkgname': 'php-twig-extra-bundle', 'pkgver': '3.3.8-2ubuntu4+esm1'},
    {'osver': '22.04', 'pkgname': 'php-twig-html-extra', 'pkgver': '3.3.8-2ubuntu4+esm1'},
    {'osver': '22.04', 'pkgname': 'php-twig-inky-extra', 'pkgver': '3.3.8-2ubuntu4+esm1'},
    {'osver': '22.04', 'pkgname': 'php-twig-intl-extra', 'pkgver': '3.3.8-2ubuntu4+esm1'},
    {'osver': '22.04', 'pkgname': 'php-twig-markdown-extra', 'pkgver': '3.3.8-2ubuntu4+esm1'},
    {'osver': '22.04', 'pkgname': 'php-twig-string-extra', 'pkgver': '3.3.8-2ubuntu4+esm1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php-twig / php-twig-cache-extra / php-twig-cssinliner-extra / etc');
}
