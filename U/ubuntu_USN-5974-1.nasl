#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5974-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173434);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2018-5685",
    "CVE-2018-9018",
    "CVE-2018-20184",
    "CVE-2018-20189",
    "CVE-2019-11006",
    "CVE-2020-12672",
    "CVE-2022-1270"
  );
  script_xref(name:"USN", value:"5974-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS : GraphicsMagick vulnerabilities (USN-5974-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5974-1 advisory.

  - In GraphicsMagick 1.4 snapshot-20181209 Q8, there is a heap-based buffer overflow in the WriteTGAImage
    function of tga.c, which allows attackers to cause a denial of service via a crafted image file, because
    the number of rows or columns can exceed the pixel-dimension restrictions of the TGA specification.
    (CVE-2018-20184)

  - In GraphicsMagick 1.3.31, the ReadDIBImage function of coders/dib.c has a vulnerability allowing a crash
    and denial of service via a dib file that is crafted to appear with direct pixel values and also
    colormapping (which is not available beyond 8-bits/sample), and therefore lacks indexes initialization.
    (CVE-2018-20189)

  - In GraphicsMagick 1.3.27, there is an infinite loop and application hang in the ReadBMPImage function
    (coders/bmp.c). Remote attackers could leverage this vulnerability to cause a denial of service via an
    image file with a crafted bit-field mask value. (CVE-2018-5685)

  - In GraphicsMagick 1.3.28, there is a divide-by-zero in the ReadMNGImage function of coders/png.c. Remote
    attackers could leverage this vulnerability to cause a crash and denial of service via a crafted mng file.
    (CVE-2018-9018)

  - In GraphicsMagick 1.4 snapshot-20190322 Q8, there is a heap-based buffer over-read in the function
    ReadMIFFImage of coders/miff.c, which allows attackers to cause a denial of service or information
    disclosure via an RLE packet. (CVE-2019-11006)

  - GraphicsMagick through 1.3.35 has a heap-based buffer overflow in ReadMNGImage in coders/png.c.
    (CVE-2020-12672)

  - In GraphicsMagick, a heap buffer overflow was found when parsing MIFF. (CVE-2022-1270)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5974-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11006");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:graphicsmagick-imagemagick-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:graphicsmagick-libmagick-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphics-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick++-q16-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick++1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick-q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgraphicsmagick3");
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
    {'osver': '16.04', 'pkgname': 'graphicsmagick', 'pkgver': '1.3.23-1ubuntu0.6+esm2'},
    {'osver': '16.04', 'pkgname': 'graphicsmagick-imagemagick-compat', 'pkgver': '1.3.23-1ubuntu0.6+esm2'},
    {'osver': '16.04', 'pkgname': 'graphicsmagick-libmagick-dev-compat', 'pkgver': '1.3.23-1ubuntu0.6+esm2'},
    {'osver': '16.04', 'pkgname': 'libgraphics-magick-perl', 'pkgver': '1.3.23-1ubuntu0.6+esm2'},
    {'osver': '16.04', 'pkgname': 'libgraphicsmagick++-q16-12', 'pkgver': '1.3.23-1ubuntu0.6+esm2'},
    {'osver': '16.04', 'pkgname': 'libgraphicsmagick++1-dev', 'pkgver': '1.3.23-1ubuntu0.6+esm2'},
    {'osver': '16.04', 'pkgname': 'libgraphicsmagick-q16-3', 'pkgver': '1.3.23-1ubuntu0.6+esm2'},
    {'osver': '16.04', 'pkgname': 'libgraphicsmagick1-dev', 'pkgver': '1.3.23-1ubuntu0.6+esm2'},
    {'osver': '18.04', 'pkgname': 'graphicsmagick', 'pkgver': '1.3.28-2ubuntu0.2+esm1'},
    {'osver': '18.04', 'pkgname': 'graphicsmagick-imagemagick-compat', 'pkgver': '1.3.28-2ubuntu0.2+esm1'},
    {'osver': '18.04', 'pkgname': 'graphicsmagick-libmagick-dev-compat', 'pkgver': '1.3.28-2ubuntu0.2+esm1'},
    {'osver': '18.04', 'pkgname': 'libgraphics-magick-perl', 'pkgver': '1.3.28-2ubuntu0.2+esm1'},
    {'osver': '18.04', 'pkgname': 'libgraphicsmagick++-q16-12', 'pkgver': '1.3.28-2ubuntu0.2+esm1'},
    {'osver': '18.04', 'pkgname': 'libgraphicsmagick++1-dev', 'pkgver': '1.3.28-2ubuntu0.2+esm1'},
    {'osver': '18.04', 'pkgname': 'libgraphicsmagick-q16-3', 'pkgver': '1.3.28-2ubuntu0.2+esm1'},
    {'osver': '18.04', 'pkgname': 'libgraphicsmagick1-dev', 'pkgver': '1.3.28-2ubuntu0.2+esm1'},
    {'osver': '20.04', 'pkgname': 'graphicsmagick', 'pkgver': '1.4+really1.3.35-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'graphicsmagick-imagemagick-compat', 'pkgver': '1.4+really1.3.35-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'graphicsmagick-libmagick-dev-compat', 'pkgver': '1.4+really1.3.35-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libgraphics-magick-perl', 'pkgver': '1.4+really1.3.35-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libgraphicsmagick++-q16-12', 'pkgver': '1.4+really1.3.35-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libgraphicsmagick++1-dev', 'pkgver': '1.4+really1.3.35-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libgraphicsmagick-q16-3', 'pkgver': '1.4+really1.3.35-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libgraphicsmagick1-dev', 'pkgver': '1.4+really1.3.35-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'graphicsmagick / graphicsmagick-imagemagick-compat / etc');
}
