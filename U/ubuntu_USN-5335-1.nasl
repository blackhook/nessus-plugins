#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5335-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159107);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2017-13144",
    "CVE-2020-19667",
    "CVE-2020-25664",
    "CVE-2020-25665",
    "CVE-2020-25674",
    "CVE-2020-25676",
    "CVE-2020-27750",
    "CVE-2020-27753",
    "CVE-2020-27760",
    "CVE-2020-27762",
    "CVE-2020-27766",
    "CVE-2020-27770",
    "CVE-2021-20176",
    "CVE-2021-20241",
    "CVE-2021-20243"
  );
  script_xref(name:"USN", value:"5335-1");
  script_xref(name:"IAVB", value:"2020-B-0042-S");

  script_name(english:"Ubuntu 16.04 LTS : ImageMagick vulnerabilities (USN-5335-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5335-1 advisory.

  - In ImageMagick before 6.9.7-10, there is a crash (rather than a width or height exceeds limit error
    report) if the image dimensions are too large, as demonstrated by use of the mpc coder. (CVE-2017-13144)

  - Stack-based buffer overflow and unconditional jump in ReadXPMImage in coders/xpm.c in ImageMagick
    7.0.10-7. (CVE-2020-19667)

  - In WriteOnePNGImage() of the PNG coder at coders/png.c, an improper call to AcquireVirtualMemory() and
    memset() allows for an out-of-bounds write later when PopShortPixel() from MagickCore/quantum-private.h is
    called. The patch fixes the calls by adding 256 to rowbytes. An attacker who is able to supply a specially
    crafted image could affect availability with a low impact to data integrity. This flaw affects ImageMagick
    versions prior to 6.9.10-68 and 7.0.8-68. (CVE-2020-25664)

  - The PALM image coder at coders/palm.c makes an improper call to AcquireQuantumMemory() in routine
    WritePALMImage() because it needs to be offset by 256. This can cause a out-of-bounds read later on in the
    routine. The patch adds 256 to bytes_per_row in the call to AcquireQuantumMemory(). This could cause
    impact to reliability. This flaw affects ImageMagick versions prior to 7.0.8-68. (CVE-2020-25665)

  - WriteOnePNGImage() from coders/png.c (the PNG coder) has a for loop with an improper exit condition that
    can allow an out-of-bounds READ via heap-buffer-overflow. This occurs because it is possible for the
    colormap to have less than 256 valid values but the loop condition will loop 256 times, attempting to pass
    invalid colormap data to the event logger. The patch replaces the hardcoded 256 value with a call to
    MagickMin() to ensure the proper value is used. This could impact application availability when a
    specially crafted input file is processed by ImageMagick. This flaw affects ImageMagick versions prior to
    7.0.8-68. (CVE-2020-25674)

  - In CatromWeights(), MeshInterpolate(), InterpolatePixelChannel(), InterpolatePixelChannels(), and
    InterpolatePixelInfo(), which are all functions in /MagickCore/pixel.c, there were multiple unconstrained
    pixel offset calculations which were being used with the floor() function. These calculations produced
    undefined behavior in the form of out-of-range and integer overflows, as identified by
    UndefinedBehaviorSanitizer. These instances of undefined behavior could be triggered by an attacker who is
    able to supply a crafted input file to be processed by ImageMagick. These issues could impact application
    availability or potentially cause other problems related to undefined behavior. This flaw affects
    ImageMagick versions prior to 7.0.9-0. (CVE-2020-25676)

  - A flaw was found in ImageMagick in MagickCore/colorspace-private.h and MagickCore/quantum.h. An attacker
    who submits a crafted file that is processed by ImageMagick could trigger undefined behavior in the form
    of values outside the range of type `unsigned char` and math division by zero. This would most likely lead
    to an impact to application availability, but could potentially cause other problems related to undefined
    behavior. This flaw affects ImageMagick versions prior to 7.0.8-68. (CVE-2020-27750)

  - There are several memory leaks in the MIFF coder in /coders/miff.c due to improper image depth values,
    which can be triggered by a specially crafted input file. These leaks could potentially lead to an impact
    to application availability or cause a denial of service. It was originally reported that the issues were
    in `AcquireMagickMemory()` because that is where LeakSanitizer detected the leaks, but the patch resolves
    issues in the MIFF coder, which incorrectly handles data being passed to `AcquireMagickMemory()`. This
    flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27753)

  - In `GammaImage()` of /MagickCore/enhance.c, depending on the `gamma` value, it's possible to trigger a
    divide-by-zero condition when a crafted input file is processed by ImageMagick. This could lead to an
    impact to application availability. The patch uses the `PerceptibleReciprocal()` to prevent the divide-by-
    zero from occurring. This flaw affects ImageMagick versions prior to ImageMagick 7.0.8-68.
    (CVE-2020-27760)

  - A flaw was found in ImageMagick in coders/hdr.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of values outside the range of type `unsigned
    char`. This would most likely lead to an impact to application availability, but could potentially cause
    other problems related to undefined behavior. This flaw affects ImageMagick versions prior to ImageMagick
    7.0.8-68. (CVE-2020-27762)

  - A flaw was found in ImageMagick in MagickCore/statistic.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of values outside the range of type
    `unsigned long`. This would most likely lead to an impact to application availability, but could
    potentially cause other problems related to undefined behavior. This flaw affects ImageMagick versions
    prior to 7.0.8-69. (CVE-2020-27766)

  - Due to a missing check for 0 value of `replace_extent`, it is possible for offset `p` to overflow in
    SubstituteString(), causing potential impact to application availability. This could be triggered by a
    crafted input file that is processed by ImageMagick. This flaw affects ImageMagick versions prior to
    7.0.8-68. (CVE-2020-27770)

  - A divide-by-zero flaw was found in ImageMagick 6.9.11-57 and 7.0.10-57 in gem.c. This flaw allows an
    attacker who submits a crafted file that is processed by ImageMagick to trigger undefined behavior through
    a division by zero. The highest threat from this vulnerability is to system availability. (CVE-2021-20176)

  - A flaw was found in ImageMagick in coders/jp2.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of math division by zero. The highest threat
    from this vulnerability is to system availability. (CVE-2021-20241)

  - A flaw was found in ImageMagick in MagickCore/resize.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20243)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5335-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27766");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-5v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '16.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagick++-6.q16-5v5', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-2', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-2-extra', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6.q16-2', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'},
    {'osver': '16.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'imagemagick / imagemagick-6.q16 / imagemagick-common / etc');
}
