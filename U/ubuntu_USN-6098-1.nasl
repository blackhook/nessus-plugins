#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6098-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176239);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2019-19035",
    "CVE-2019-1010301",
    "CVE-2019-1010302",
    "CVE-2020-6624",
    "CVE-2020-6625",
    "CVE-2020-26208",
    "CVE-2021-28276",
    "CVE-2021-28278"
  );
  script_xref(name:"USN", value:"6098-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS : Jhead vulnerabilities (USN-6098-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple
vulnerabilities as referenced in the USN-6098-1 advisory.

  - jhead 3.03 is affected by: Buffer Overflow. The impact is: Denial of service. The component is: gpsinfo.c
    Line 151 ProcessGpsInfo(). The attack vector is: Open a specially crafted JPEG file. (CVE-2019-1010301)

  - jhead 3.03 is affected by: Incorrect Access Control. The impact is: Denial of service. The component is:
    iptc.c Line 122 show_IPTC(). The attack vector is: the victim must open a specially crafted JPEG file.
    (CVE-2019-1010302)

  - jhead 3.03 is affected by: heap-based buffer over-read. The impact is: Denial of service. The component
    is: ReadJpegSections and process_SOFn in jpgfile.c. The attack vector is: Open a specially crafted JPEG
    file. (CVE-2019-19035)

  - JHEAD is a simple command line tool for displaying and some manipulation of EXIF header data embedded in
    Jpeg images from digital cameras. In affected versions there is a heap-buffer-overflow on
    jhead-3.04/jpgfile.c:285 ReadJpegSections. Crafted jpeg images can be provided to the user resulting in a
    program crash or potentially incorrect exif information retrieval. Users are advised to upgrade. There is
    no known workaround for this issue. (CVE-2020-26208)

  - jhead through 3.04 has a heap-based buffer over-read in process_DQT in jpgqguess.c. (CVE-2020-6624)

  - jhead through 3.04 has a heap-based buffer over-read in Get32s when called from ProcessGpsInfo in
    gpsinfo.c. (CVE-2020-6625)

  - A Denial of Service vulnerability exists in jhead 3.04 and 3.05 via a wild address read in the
    ProcessCanonMakerNoteDir function in makernote.c. (CVE-2021-28276)

  - A Heap-based Buffer Overflow vulnerability exists in jhead 3.04 and 3.05 via the RemoveSectionType
    function in jpgfile.c. (CVE-2021-28278)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6098-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected jhead package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28278");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:jhead");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'jhead', 'pkgver': '1:3.00-4+deb9u1ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'jhead', 'pkgver': '1:3.00-8~ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'jhead', 'pkgver': '1:3.04-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jhead');
}
