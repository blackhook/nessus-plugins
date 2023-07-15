#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5227-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156742);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-23437",
    "CVE-2021-34552",
    "CVE-2022-22815",
    "CVE-2022-22816",
    "CVE-2022-22817"
  );
  script_xref(name:"USN", value:"5227-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.04 / 21.10 : Pillow vulnerabilities (USN-5227-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.04 / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5227-1 advisory.

  - The package pillow 5.2.0 and before 8.3.2 are vulnerable to Regular Expression Denial of Service (ReDoS)
    via the getrgb function. (CVE-2021-23437)

  - Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass
    controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.
    (CVE-2021-34552)

  - path_getbbox in path.c in Pillow before 9.0.0 improperly initializes ImagePath.Path. (CVE-2022-22815)

  - path_getbbox in path.c in Pillow before 9.0.0 has a buffer over-read during initialization of
    ImagePath.Path. (CVE-2022-22816)

  - PIL.ImageMath.eval in Pillow before 9.0.0 allows evaluation of arbitrary expressions, such as ones that
    use the Python exec method. (CVE-2022-22817)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5227-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34552");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-pil.imagetk");
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
if (! preg(pattern:"^(18\.04|20\.04|21\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'python-pil', 'pkgver': '5.1.0-1ubuntu0.7'},
    {'osver': '18.04', 'pkgname': 'python-pil.imagetk', 'pkgver': '5.1.0-1ubuntu0.7'},
    {'osver': '18.04', 'pkgname': 'python3-pil', 'pkgver': '5.1.0-1ubuntu0.7'},
    {'osver': '18.04', 'pkgname': 'python3-pil.imagetk', 'pkgver': '5.1.0-1ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'python3-pil', 'pkgver': '7.0.0-4ubuntu0.5'},
    {'osver': '20.04', 'pkgname': 'python3-pil.imagetk', 'pkgver': '7.0.0-4ubuntu0.5'},
    {'osver': '21.04', 'pkgname': 'python3-pil', 'pkgver': '8.1.2-1ubuntu0.2'},
    {'osver': '21.04', 'pkgname': 'python3-pil.imagetk', 'pkgver': '8.1.2-1ubuntu0.2'},
    {'osver': '21.10', 'pkgname': 'python3-pil', 'pkgver': '8.1.2+dfsg-0.3ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'python3-pil.imagetk', 'pkgver': '8.1.2+dfsg-0.3ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-pil / python-pil.imagetk / python3-pil / python3-pil.imagetk');
}
