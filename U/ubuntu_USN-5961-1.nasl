#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5961-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172617);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id(
    "CVE-2018-10753",
    "CVE-2018-10771",
    "CVE-2019-1010069",
    "CVE-2021-32434",
    "CVE-2021-32435",
    "CVE-2021-32436"
  );
  script_xref(name:"USN", value:"5961-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 ESM / 22.04 ESM : abcm2ps vulnerabilities (USN-5961-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 ESM / 22.04 ESM host has a package installed that is affected by
multiple vulnerabilities as referenced in the USN-5961-1 advisory.

  - Stack-based buffer overflow in the delayed_output function in music.c in abcm2ps through 8.13.20 allows
    remote attackers to cause a denial of service (application crash) or possibly have unspecified other
    impact. (CVE-2018-10753)

  - Stack-based buffer overflow in the get_key function in parse.c in abcm2ps through 8.13.20 allows remote
    attackers to cause a denial of service (application crash) or possibly have unspecified other impact.
    (CVE-2018-10771)

  - moinejf abcm2ps 8.13.20 is affected by: Incorrect Access Control. The impact is: Allows attackers to cause
    a denial of service attack via a crafted file. The component is: front.c, function txt_add. The fixed
    version is: after commit commit 08aef597656d065e86075f3d53fda89765845eae. (CVE-2019-1010069)

  - abcm2ps v8.14.11 was discovered to contain an out-of-bounds read in the function calculate_beam at draw.c.
    (CVE-2021-32434)

  - Stack-based buffer overflow in the function get_key in parse.c of abcm2ps v8.14.11 allows remote attackers
    to cause a Denial of Service (DoS) via unspecified vectors. (CVE-2021-32435)

  - An out-of-bounds read in the function write_title() in subs.c of abcm2ps v8.14.11 allows remote attackers
    to cause a Denial of Service (DoS) via unspecified vectors. (CVE-2021-32436)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5961-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected abcm2ps package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10771");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abcm2ps");
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
    {'osver': '16.04', 'pkgname': 'abcm2ps', 'pkgver': '7.8.9-1ubuntu0.16.04.1~esm1'},
    {'osver': '18.04', 'pkgname': 'abcm2ps', 'pkgver': '7.8.9-1+deb9u1build0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'abcm2ps', 'pkgver': '8.14.6-0.1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'abcm2ps', 'pkgver': '8.14.11-0.1ubuntu0.1~esm1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'abcm2ps');
}
