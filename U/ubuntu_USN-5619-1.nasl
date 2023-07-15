#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5619-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165277);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-19131",
    "CVE-2020-19144",
    "CVE-2022-1354",
    "CVE-2022-1355",
    "CVE-2022-2056",
    "CVE-2022-2057",
    "CVE-2022-2058"
  );
  script_xref(name:"USN", value:"5619-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS : LibTIFF vulnerabilities (USN-5619-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5619-1 advisory.

  - Buffer Overflow in LibTiff v4.0.10 allows attackers to cause a denial of service via the invertImage()
    function in the component tiffcrop. (CVE-2020-19131)

  - Buffer Overflow in LibTiff v4.0.10 allows attackers to cause a denial of service via the 'in _TIFFmemcpy'
    funtion in the component 'tif_unix.c'. (CVE-2020-19144)

  - A heap buffer overflow flaw was found in Libtiffs' tiffinfo.c in TIFFReadRawDataStriped() function. This
    flaw allows an attacker to pass a crafted TIFF file to the tiffinfo tool, triggering a heap buffer
    overflow issue and causing a crash that leads to a denial of service. (CVE-2022-1354)

  - A stack buffer overflow flaw was found in Libtiffs' tiffcp.c in main() function. This flaw allows an
    attacker to pass a crafted TIFF file to the tiffcp tool, triggering a stack buffer overflow issue,
    possibly corrupting the memory, and causing a crash that leads to a denial of service. (CVE-2022-1355)

  - Divide By Zero error in tiffcrop in libtiff 4.4.0 allows attackers to cause a denial-of-service via a
    crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f3a5e010.
    (CVE-2022-2056, CVE-2022-2057, CVE-2022-2058)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5619-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-19131");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1355");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff5-alt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiffxx5");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libtiff-opengl', 'pkgver': '4.0.6-1ubuntu0.8+esm4'},
    {'osver': '16.04', 'pkgname': 'libtiff-tools', 'pkgver': '4.0.6-1ubuntu0.8+esm4'},
    {'osver': '16.04', 'pkgname': 'libtiff5', 'pkgver': '4.0.6-1ubuntu0.8+esm4'},
    {'osver': '16.04', 'pkgname': 'libtiff5-dev', 'pkgver': '4.0.6-1ubuntu0.8+esm4'},
    {'osver': '16.04', 'pkgname': 'libtiffxx5', 'pkgver': '4.0.6-1ubuntu0.8+esm4'},
    {'osver': '18.04', 'pkgname': 'libtiff-dev', 'pkgver': '4.0.9-5ubuntu0.7'},
    {'osver': '18.04', 'pkgname': 'libtiff-opengl', 'pkgver': '4.0.9-5ubuntu0.7'},
    {'osver': '18.04', 'pkgname': 'libtiff-tools', 'pkgver': '4.0.9-5ubuntu0.7'},
    {'osver': '18.04', 'pkgname': 'libtiff5', 'pkgver': '4.0.9-5ubuntu0.7'},
    {'osver': '18.04', 'pkgname': 'libtiff5-dev', 'pkgver': '4.0.9-5ubuntu0.7'},
    {'osver': '18.04', 'pkgname': 'libtiffxx5', 'pkgver': '4.0.9-5ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libtiff-dev', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.5'},
    {'osver': '20.04', 'pkgname': 'libtiff-opengl', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.5'},
    {'osver': '20.04', 'pkgname': 'libtiff-tools', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.5'},
    {'osver': '20.04', 'pkgname': 'libtiff5', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.5'},
    {'osver': '20.04', 'pkgname': 'libtiff5-dev', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.5'},
    {'osver': '20.04', 'pkgname': 'libtiffxx5', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.5'},
    {'osver': '22.04', 'pkgname': 'libtiff-dev', 'pkgver': '4.3.0-6ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtiff-opengl', 'pkgver': '4.3.0-6ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtiff-tools', 'pkgver': '4.3.0-6ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtiff5', 'pkgver': '4.3.0-6ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtiff5-dev', 'pkgver': '4.3.0-6ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtiffxx5', 'pkgver': '4.3.0-6ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtiff-dev / libtiff-opengl / libtiff-tools / libtiff5 / libtiff5-dev / etc');
}
