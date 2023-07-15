#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4988-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150793);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2017-14528",
    "CVE-2020-19667",
    "CVE-2020-25665",
    "CVE-2020-25666",
    "CVE-2020-25674",
    "CVE-2020-25675",
    "CVE-2020-25676",
    "CVE-2020-27750",
    "CVE-2020-27751",
    "CVE-2020-27753",
    "CVE-2020-27754",
    "CVE-2020-27755",
    "CVE-2020-27756",
    "CVE-2020-27757",
    "CVE-2020-27758",
    "CVE-2020-27759",
    "CVE-2020-27760",
    "CVE-2020-27761",
    "CVE-2020-27762",
    "CVE-2020-27763",
    "CVE-2020-27764",
    "CVE-2020-27765",
    "CVE-2020-27766",
    "CVE-2020-27767",
    "CVE-2020-27768",
    "CVE-2020-27769",
    "CVE-2020-27770",
    "CVE-2020-27771",
    "CVE-2020-27772",
    "CVE-2020-27773",
    "CVE-2020-27774",
    "CVE-2020-27775",
    "CVE-2020-27776",
    "CVE-2021-20176"
  );
  script_xref(name:"USN", value:"4988-1");
  script_xref(name:"IAVB", value:"2020-B-0042-S");
  script_xref(name:"IAVB", value:"2020-B-0076-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 : ImageMagick vulnerabilities (USN-4988-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4988-1 advisory.

  - The TIFFSetProfiles function in coders/tiff.c in ImageMagick 7.0.6 has incorrect expectations about
    whether LibTIFF TIFFGetField return values imply that data validation has occurred, which allows remote
    attackers to cause a denial of service (use-after-free after an invalid call to TIFFSetField, and
    application crash) via a crafted file. (CVE-2017-14528)

  - Stack-based buffer overflow and unconditional jump in ReadXPMImage in coders/xpm.c in ImageMagick
    7.0.10-7. (CVE-2020-19667)

  - The PALM image coder at coders/palm.c makes an improper call to AcquireQuantumMemory() in routine
    WritePALMImage() because it needs to be offset by 256. This can cause a out-of-bounds read later on in the
    routine. The patch adds 256 to bytes_per_row in the call to AcquireQuantumMemory(). This could cause
    impact to reliability. This flaw affects ImageMagick versions prior to 7.0.8-68. (CVE-2020-25665)

  - There are 4 places in HistogramCompare() in MagickCore/histogram.c where an integer overflow is possible
    during simple math calculations. This occurs in the rgb values and `count` value for a color. The patch
    uses casts to `ssize_t` type for these calculations, instead of `int`. This flaw could impact application
    reliability in the event that ImageMagick processes a crafted input file. This flaw affects ImageMagick
    versions prior to 7.0.9-0. (CVE-2020-25666)

  - WriteOnePNGImage() from coders/png.c (the PNG coder) has a for loop with an improper exit condition that
    can allow an out-of-bounds READ via heap-buffer-overflow. This occurs because it is possible for the
    colormap to have less than 256 valid values but the loop condition will loop 256 times, attempting to pass
    invalid colormap data to the event logger. The patch replaces the hardcoded 256 value with a call to
    MagickMin() to ensure the proper value is used. This could impact application availability when a
    specially crafted input file is processed by ImageMagick. This flaw affects ImageMagick versions prior to
    7.0.8-68. (CVE-2020-25674)

  - In the CropImage() and CropImageToTiles() routines of MagickCore/transform.c, rounding calculations
    performed on unconstrained pixel offsets was causing undefined behavior in the form of integer overflow
    and out-of-range values as reported by UndefinedBehaviorSanitizer. Such issues could cause a negative
    impact to application availability or other problems related to undefined behavior, in cases where
    ImageMagick processes untrusted input data. The upstream patch introduces functionality to constrain the
    pixel offsets and prevent these issues. This flaw affects ImageMagick versions prior to 7.0.9-0.
    (CVE-2020-25675)

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

  - A flaw was found in ImageMagick in MagickCore/quantum-export.c. An attacker who submits a crafted file
    that is processed by ImageMagick could trigger undefined behavior in the form of values outside the range
    of type `unsigned long long` as well as a shift exponent that is too large for 64-bit type. This would
    most likely lead to an impact to application availability, but could potentially cause other problems
    related to undefined behavior. This flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27751)

  - There are several memory leaks in the MIFF coder in /coders/miff.c due to improper image depth values,
    which can be triggered by a specially crafted input file. These leaks could potentially lead to an impact
    to application availability or cause a denial of service. It was originally reported that the issues were
    in `AcquireMagickMemory()` because that is where LeakSanitizer detected the leaks, but the patch resolves
    issues in the MIFF coder, which incorrectly handles data being passed to `AcquireMagickMemory()`. This
    flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27753)

  - In IntensityCompare() of /magick/quantize.c, there are calls to PixelPacketIntensity() which could return
    overflowed values to the caller when ImageMagick processes a crafted input file. To mitigate this, the
    patch introduces and uses the ConstrainPixelIntensity() function, which forces the pixel intensities to be
    within the proper bounds in the event of an overflow. This flaw affects ImageMagick versions prior to
    6.9.10-69 and 7.0.8-69. (CVE-2020-27754)

  - in SetImageExtent() of /MagickCore/image.c, an incorrect image depth size can cause a memory leak because
    the code which checks for the proper image depth size does not reset the size in the event there is an
    invalid size. The patch resets the depth to a proper size before throwing an exception. The memory leak
    can be triggered by a crafted input file that is processed by ImageMagick and could cause an impact to
    application reliability, such as denial of service. This flaw affects ImageMagick versions prior to
    7.0.9-0. (CVE-2020-27755)

  - In ParseMetaGeometry() of MagickCore/geometry.c, image height and width calculations can lead to divide-
    by-zero conditions which also lead to undefined behavior. This flaw can be triggered by a crafted input
    file processed by ImageMagick and could impact application availability. The patch uses multiplication in
    addition to the function `PerceptibleReciprocal()` in order to prevent such divide-by-zero conditions.
    This flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27756)

  - A floating point math calculation in ScaleAnyToQuantum() of /MagickCore/quantum-private.h could lead to
    undefined behavior in the form of a value outside the range of type unsigned long long. The flaw could be
    triggered by a crafted input file under certain conditions when it is processed by ImageMagick. Red Hat
    Product Security marked this as Low because although it could potentially lead to an impact to application
    availability, no specific impact was shown in this case. This flaw affects ImageMagick versions prior to
    7.0.8-68. (CVE-2020-27757)

  - A flaw was found in ImageMagick in coders/txt.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of values outside the range of type `unsigned
    long long`. This would most likely lead to an impact to application availability, but could potentially
    cause other problems related to undefined behavior. This flaw affects ImageMagick versions prior to
    7.0.8-68. (CVE-2020-27758)

  - In IntensityCompare() of /MagickCore/quantize.c, a double value was being casted to int and returned,
    which in some cases caused a value outside the range of type `int` to be returned. The flaw could be
    triggered by a crafted input file under certain conditions when processed by ImageMagick. Red Hat Product
    Security marked this as Low severity because although it could potentially lead to an impact to
    application availability, no specific impact was shown in this case. This flaw affects ImageMagick
    versions prior to 7.0.8-68. (CVE-2020-27759)

  - In `GammaImage()` of /MagickCore/enhance.c, depending on the `gamma` value, it's possible to trigger a
    divide-by-zero condition when a crafted input file is processed by ImageMagick. This could lead to an
    impact to application availability. The patch uses the `PerceptibleReciprocal()` to prevent the divide-by-
    zero from occurring. This flaw affects ImageMagick versions prior to ImageMagick 7.0.8-68.
    (CVE-2020-27760)

  - WritePALMImage() in /coders/palm.c used size_t casts in several areas of a calculation which could lead to
    values outside the range of representable type `unsigned long` undefined behavior when a crafted input
    file was processed by ImageMagick. The patch casts to `ssize_t` instead to avoid this issue. Red Hat
    Product Security marked the Severity as Low because although it could potentially lead to an impact to
    application availability, no specific impact was shown in this case. This flaw affects ImageMagick
    versions prior to ImageMagick 7.0.9-0. (CVE-2020-27761)

  - A flaw was found in ImageMagick in coders/hdr.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of values outside the range of type `unsigned
    char`. This would most likely lead to an impact to application availability, but could potentially cause
    other problems related to undefined behavior. This flaw affects ImageMagick versions prior to ImageMagick
    7.0.8-68. (CVE-2020-27762)

  - A flaw was found in ImageMagick in MagickCore/resize.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. This would
    most likely lead to an impact to application availability, but could potentially cause other problems
    related to undefined behavior. This flaw affects ImageMagick versions prior to 7.0.8-68. (CVE-2020-27763)

  - In /MagickCore/statistic.c, there are several areas in ApplyEvaluateOperator() where a size_t cast should
    have been a ssize_t cast, which causes out-of-range values under some circumstances when a crafted input
    file is processed by ImageMagick. Red Hat Product Security marked this as Low severity because although it
    could potentially lead to an impact to application availability, no specific impact was shown in this
    case. This flaw affects ImageMagick versions prior to 6.9.10-69. (CVE-2020-27764)

  - A flaw was found in ImageMagick in MagickCore/segment.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. This would
    most likely lead to an impact to application availability, but could potentially cause other problems
    related to undefined behavior. This flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27765)

  - A flaw was found in ImageMagick in MagickCore/statistic.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of values outside the range of type
    `unsigned long`. This would most likely lead to an impact to application availability, but could
    potentially cause other problems related to undefined behavior. This flaw affects ImageMagick versions
    prior to 7.0.8-69. (CVE-2020-27766)

  - A flaw was found in ImageMagick in MagickCore/quantum.h. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of values outside the range of types
    `float` and `unsigned char`. This would most likely lead to an impact to application availability, but
    could potentially cause other problems related to undefined behavior. This flaw affects ImageMagick
    versions prior to 7.0.9-0. (CVE-2020-27767)

  - In ImageMagick, there is an outside the range of representable values of type 'unsigned int' at
    MagickCore/quantum-private.h. This flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27768)

  - In ImageMagick versions before 7.0.9-0, there are outside the range of representable values of type
    'float' at MagickCore/quantize.c. (CVE-2020-27769)

  - Due to a missing check for 0 value of `replace_extent`, it is possible for offset `p` to overflow in
    SubstituteString(), causing potential impact to application availability. This could be triggered by a
    crafted input file that is processed by ImageMagick. This flaw affects ImageMagick versions prior to
    7.0.8-68. (CVE-2020-27770)

  - In RestoreMSCWarning() of /coders/pdf.c there are several areas where calls to GetPixelIndex() could
    result in values outside the range of representable for the unsigned char type. The patch casts the return
    value of GetPixelIndex() to ssize_t type to avoid this bug. This undefined behavior could be triggered
    when ImageMagick processes a crafted pdf file. Red Hat Product Security marked this as Low severity
    because although it could potentially lead to an impact to application availability, no specific impact
    was demonstrated in this case. This flaw affects ImageMagick versions prior to 7.0.9-0. (CVE-2020-27771)

  - A flaw was found in ImageMagick in coders/bmp.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of values outside the range of type `unsigned
    int`. This would most likely lead to an impact to application availability, but could potentially cause
    other problems related to undefined behavior. This flaw affects ImageMagick versions prior to 7.0.9-0.
    (CVE-2020-27772)

  - A flaw was found in ImageMagick in MagickCore/gem-private.h. An attacker who submits a crafted file that
    is processed by ImageMagick could trigger undefined behavior in the form of values outside the range of
    type `unsigned char` or division by zero. This would most likely lead to an impact to application
    availability, but could potentially cause other problems related to undefined behavior. This flaw affects
    ImageMagick versions prior to 7.0.9-0. (CVE-2020-27773)

  - A flaw was found in ImageMagick in MagickCore/statistic.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of a too large shift for 64-bit type
    `ssize_t`. This would most likely lead to an impact to application availability, but could potentially
    cause other problems related to undefined behavior. This flaw affects ImageMagick versions prior to
    7.0.9-0. (CVE-2020-27774)

  - A flaw was found in ImageMagick in MagickCore/quantum.h. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of values outside the range of type
    unsigned char. This would most likely lead to an impact to application availability, but could potentially
    cause other problems related to undefined behavior. This flaw affects ImageMagick versions prior to
    7.0.9-0. (CVE-2020-27775)

  - A flaw was found in ImageMagick in MagickCore/statistic.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of values outside the range of type
    unsigned long. This would most likely lead to an impact to application availability, but could potentially
    cause other problems related to undefined behavior. This flaw affects ImageMagick versions prior to
    7.0.9-0. (CVE-2020-27776)

  - A divide-by-zero flaw was found in ImageMagick 6.9.11-57 and 7.0.10-57 in gem.c. This flaw allows an
    attacker who submits a crafted file that is processed by ImageMagick to trigger undefined behavior through
    a division by zero. The highest threat from this vulnerability is to system availability. (CVE-2021-20176)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4988-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27766");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16hdri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-q16hdri-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16-7', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16hdri-7', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-3-extra', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-3-extra', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16hdri-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '18.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.11'},
    {'osver': '20.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.4'},
    {'osver': '20.10', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'},
    {'osver': '20.10', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu13.3'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'imagemagick / imagemagick-6-common / imagemagick-6.q16 / etc');
}
