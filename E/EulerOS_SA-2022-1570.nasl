#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160159);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id(
    "CVE-2018-9133",
    "CVE-2018-16323",
    "CVE-2018-16750",
    "CVE-2018-20467",
    "CVE-2019-14980",
    "CVE-2019-14981",
    "CVE-2020-25665",
    "CVE-2020-25666",
    "CVE-2020-25667",
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
    "CVE-2021-20241",
    "CVE-2021-20243",
    "CVE-2021-20244",
    "CVE-2021-20246"
  );
  script_xref(name:"IAVB", value:"2020-B-0076-S");
  script_xref(name:"IAVB", value:"2021-B-0017-S");

  script_name(english:"EulerOS 2.0 SP8 : ImageMagick (EulerOS-SA-2022-1570)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ImageMagick packages installed, the EulerOS installation on the remote host is affected
by the following vulnerabilities :

  - ReadXBMImage in coders/xbm.c in ImageMagick before 7.0.8-9 leaves data uninitialized when processing an
    XBM file that has a negative pixel value. If the affected code is used as a library loaded into a process
    that includes sensitive information, that information sometimes can be leaked via the image data.
    (CVE-2018-16323)

  - In ImageMagick 7.0.7-29 and earlier, a memory leak in the formatIPTCfromBuffer function in coders/meta.c
    was found. (CVE-2018-16750)

  - In coders/bmp.c in ImageMagick before 7.0.8-16, an input file can result in an infinite loop and hang,
    with high CPU and memory consumption. Remote attackers could leverage this vulnerability to cause a denial
    of service via a crafted file. (CVE-2018-20467)

  - ImageMagick 7.0.7-26 Q16 has excessive iteration in the DecodeLabImage and EncodeLabImage functions
    (coders/tiff.c), which results in a hang (tens of minutes) with a tiny PoC file. Remote attackers could
    leverage this vulnerability to cause a denial of service via a crafted tiff file. (CVE-2018-9133)

  - In ImageMagick 7.x before 7.0.8-42 and 6.x before 6.9.10-42, there is a use after free vulnerability in
    the UnmapBlob function that allows an attacker to cause a denial of service by sending a crafted file.
    (CVE-2019-14980)

  - In ImageMagick 7.x before 7.0.8-41 and 6.x before 6.9.10-41, there is a divide-by-zero vulnerability in
    the MeanShiftImage function. It allows an attacker to cause a denial of service by sending a crafted file.
    (CVE-2019-14981)

  - The PALM image coder at coders/palm.c makes an improper call to AcquireQuantumMemory() in routine
    WritePALMImage() because it needs to be offset by 256. This can cause a out-of-bounds read later on in the
    routine. The patch adds 256 to bytes_per_row in the call to AcquireQuantumMemory(). This could cause
    impact to reliability. This flaw affects ImageMagick versions prior to 7.0.8-68. (CVE-2020-25665)

  - There are 4 places in HistogramCompare() in MagickCore/histogram.c where an integer overflow is possible
    during simple math calculations. This occurs in the rgb values and `count` value for a color. The patch
    uses casts to `ssize_t` type for these calculations, instead of `int`. This flaw could impact application
    reliability in the event that ImageMagick processes a crafted input file. This flaw affects ImageMagick
    versions prior to 7.0.9-0. (CVE-2020-25666)

  - TIFFGetProfiles() in /coders/tiff.c calls strstr() which causes a large out-of-bounds read when it
    searches for `'dc:format=\'image/dng\'` within `profile` due to improper string handling, when a crafted
    input file is provided to ImageMagick. The patch uses a StringInfo type instead of a raw C string to
    remedy this. This could cause an impact to availability of the application. This flaw affects ImageMagick
    versions prior to 7.0.9-0. (CVE-2020-25667)

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

  - A flaw was found in ImageMagick in coders/jp2.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of math division by zero. The highest threat
    from this vulnerability is to system availability. (CVE-2021-20241)

  - A flaw was found in ImageMagick in MagickCore/resize.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20243)

  - A flaw was found in ImageMagick in MagickCore/visual-effects.c. An attacker who submits a crafted file
    that is processed by ImageMagick could trigger undefined behavior in the form of math division by zero.
    The highest threat from this vulnerability is to system availability. (CVE-2021-20244)

  - A flaw was found in ImageMagick in MagickCore/resample.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20246)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1570
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e927592b");
  script_set_attribute(attribute:"solution", value:
"Update the affected ImageMagick packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16323");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "ImageMagick-6.9.9.38-3.h24.eulerosv2r8",
  "ImageMagick-c++-6.9.9.38-3.h24.eulerosv2r8",
  "ImageMagick-libs-6.9.9.38-3.h24.eulerosv2r8",
  "ImageMagick-perl-6.9.9.38-3.h24.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
