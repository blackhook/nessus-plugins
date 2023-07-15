#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3357. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172481);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id(
    "CVE-2020-19667",
    "CVE-2020-25665",
    "CVE-2020-25666",
    "CVE-2020-25674",
    "CVE-2020-25675",
    "CVE-2020-25676",
    "CVE-2020-27560",
    "CVE-2020-27750",
    "CVE-2020-27751",
    "CVE-2020-27754",
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
    "CVE-2020-29599",
    "CVE-2021-3574",
    "CVE-2021-3596",
    "CVE-2021-20224",
    "CVE-2022-44267",
    "CVE-2022-44268"
  );
  script_xref(name:"IAVB", value:"2020-B-0042-S");
  script_xref(name:"IAVB", value:"2020-B-0076-S");
  script_xref(name:"IAVB", value:"2022-B-0032-S");
  script_xref(name:"IAVB", value:"2023-B-0006-S");

  script_name(english:"Debian DLA-3357-1 : imagemagick - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3357 advisory.

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

  - ImageMagick 7.0.10-34 allows Division by Zero in OptimizeLayerFrames in MagickCore/layer.c, which may
    cause a denial of service. (CVE-2020-27560)

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

  - In IntensityCompare() of /magick/quantize.c, there are calls to PixelPacketIntensity() which could return
    overflowed values to the caller when ImageMagick processes a crafted input file. To mitigate this, the
    patch introduces and uses the ConstrainPixelIntensity() function, which forces the pixel intensities to be
    within the proper bounds in the event of an overflow. This flaw affects ImageMagick versions prior to
    6.9.10-69 and 7.0.8-69. (CVE-2020-27754)

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

  - ImageMagick before 6.9.11-40 and 7.x before 7.0.10-40 mishandles the -authenticate option, which allows
    setting a password for password-protected PDF files. The user-controlled password was not properly
    escaped/sanitized and it was therefore possible to inject additional shell commands via coders/pdf.c.
    (CVE-2020-29599)

  - An integer overflow issue was discovered in ImageMagick's ExportIndexQuantum() function in
    MagickCore/quantum-export.c. Function calls to GetPixelIndex() could result in values outside the range of
    representable for the 'unsigned char'. When ImageMagick processes a crafted pdf file, this could lead to
    an undefined behaviour or a crash. (CVE-2021-20224)

  - A vulnerability was found in ImageMagick-7.0.11-5, where executing a crafted file with the convert
    command, ASAN detects memory leaks. (CVE-2021-3574)

  - A NULL pointer dereference flaw was found in ImageMagick in versions prior to 7.0.10-31 in ReadSVGImage()
    in coders/svg.c. This issue is due to not checking the return value from libxml2's
    xmlCreatePushParserCtxt() and uses the value directly, which leads to a crash and segmentation fault.
    (CVE-2021-3596)

  - ImageMagick 7.1.0-49 is vulnerable to Denial of Service. When it parses a PNG image (e.g., for resize),
    the convert process could be left waiting for stdin input. (CVE-2022-44267)

  - ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for
    resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary
    has permissions to read it). (CVE-2022-44268)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1027164");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/imagemagick");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3357");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-19667");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25665");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25666");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25674");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25675");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25676");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27560");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27750");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27751");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27754");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27756");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27757");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27758");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27759");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27761");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27762");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27764");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27765");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27766");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27767");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27768");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27769");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27770");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27771");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27772");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27773");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27774");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27775");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27776");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-29599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20224");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3574");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3596");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44267");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44268");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/imagemagick");
  script_set_attribute(attribute:"solution", value:
"Upgrade the imagemagick packages.

For Debian 10 buster, these problems have been fixed in version 8");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29599");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16hdri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16hdri-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'imagemagick', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'imagemagick-6-common', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'imagemagick-6-doc', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'imagemagick-6.q16', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'imagemagick-6.q16hdri', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'imagemagick-common', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'imagemagick-doc', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libimage-magick-perl', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libimage-magick-q16-perl', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libimage-magick-q16hdri-perl', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagick++-6-headers', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16-8', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16hdri-8', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16hdri-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagick++-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickcore-6-arch-config', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickcore-6-headers', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16-6-extra', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16hdri-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16hdri-6-extra', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16hdri-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickcore-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickwand-6-headers', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16hdri-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16hdri-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libmagickwand-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'},
    {'release': '10.0', 'prefix': 'perlmagick', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'imagemagick / imagemagick-6-common / imagemagick-6-doc / etc');
}
