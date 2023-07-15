#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2799. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154752);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/31");

  script_cve_id(
    "CVE-2016-1516",
    "CVE-2017-12597",
    "CVE-2017-12598",
    "CVE-2017-12599",
    "CVE-2017-12601",
    "CVE-2017-12603",
    "CVE-2017-12604",
    "CVE-2017-12605",
    "CVE-2017-12606",
    "CVE-2017-12862",
    "CVE-2017-12863",
    "CVE-2017-12864",
    "CVE-2017-17760",
    "CVE-2017-1000450",
    "CVE-2018-5268",
    "CVE-2018-5269",
    "CVE-2019-14493",
    "CVE-2019-15939"
  );

  script_name(english:"Debian DLA-2799-1 : opencv - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2799 advisory.

  - OpenCV 3.0.0 has a double free issue that allows attackers to execute arbitrary code. (CVE-2016-1516)

  - In opencv/modules/imgcodecs/src/utils.cpp, functions FillUniColor and FillUniGray do not check the input
    length, which can lead to integer overflow. If the image is from remote, may lead to remote code execution
    or denial of service. This affects Opencv 3.3 and earlier. (CVE-2017-1000450)

  - OpenCV (Open Source Computer Vision Library) through 3.3 has an out-of-bounds write error in the function
    FillColorRow1 in utils.cpp when reading an image file by using cv::imread. (CVE-2017-12597)

  - OpenCV (Open Source Computer Vision Library) through 3.3 has an out-of-bounds read error in the
    cv::RBaseStream::readBlock function in modules/imgcodecs/src/bitstrm.cpp when reading an image file by
    using cv::imread, as demonstrated by the 8-opencv-invalid-read-fread test case. (CVE-2017-12598)

  - OpenCV (Open Source Computer Vision Library) through 3.3 has an out-of-bounds read error in the function
    icvCvt_BGRA2BGR_8u_C4C3R when reading an image file by using cv::imread. (CVE-2017-12599)

  - OpenCV (Open Source Computer Vision Library) through 3.3 has a buffer overflow in the
    cv::BmpDecoder::readData function in modules/imgcodecs/src/grfmt_bmp.cpp when reading an image file by
    using cv::imread, as demonstrated by the 4-buf-overflow-readData-memcpy test case. (CVE-2017-12601)

  - OpenCV (Open Source Computer Vision Library) through 3.3 has an invalid write in the
    cv::RLByteStream::getBytes function in modules/imgcodecs/src/bitstrm.cpp when reading an image file by
    using cv::imread, as demonstrated by the 2-opencv-heapoverflow-fseek test case. (CVE-2017-12603)

  - OpenCV (Open Source Computer Vision Library) through 3.3 has an out-of-bounds write error in the
    FillUniColor function in utils.cpp when reading an image file by using cv::imread. (CVE-2017-12604)

  - OpenCV (Open Source Computer Vision Library) through 3.3 has an out-of-bounds write error in the
    FillColorRow8 function in utils.cpp when reading an image file by using cv::imread. (CVE-2017-12605)

  - OpenCV (Open Source Computer Vision Library) through 3.3 has an out-of-bounds write error in the function
    FillColorRow4 in utils.cpp when reading an image file by using cv::imread. (CVE-2017-12606)

  - In modules/imgcodecs/src/grfmt_pxm.cpp, the length of buffer AutoBuffer _src is small than expected, which
    will cause copy buffer overflow later. If the image is from remote, may lead to remote code execution or
    denial of service. This affects Opencv 3.3 and earlier. (CVE-2017-12862)

  - In opencv/modules/imgcodecs/src/grfmt_pxm.cpp, function PxMDecoder::readData has an integer overflow when
    calculate src_pitch. If the image is from remote, may lead to remote code execution or denial of service.
    This affects Opencv 3.3 and earlier. (CVE-2017-12863)

  - In opencv/modules/imgcodecs/src/grfmt_pxm.cpp, function ReadNumber did not checkout the input length,
    which lead to integer overflow. If the image is from remote, may lead to remote code execution or denial
    of service. This affects Opencv 3.3 and earlier. (CVE-2017-12864)

  - OpenCV 3.3.1 has a Buffer Overflow in the cv::PxMDecoder::readData function in grfmt_pxm.cpp, because an
    incorrect size value is used. (CVE-2017-17760)

  - In OpenCV 3.3.1, a heap-based buffer overflow happens in cv::Jpeg2KDecoder::readComponent8u in
    modules/imgcodecs/src/grfmt_jpeg2000.cpp when parsing a crafted image file. (CVE-2018-5268)

  - In OpenCV 3.3.1, an assertion failure happens in cv::RBaseStream::setPos in
    modules/imgcodecs/src/bitstrm.cpp because of an incorrect integer cast. (CVE-2018-5269)

  - An issue was discovered in OpenCV before 4.1.1. There is a NULL pointer dereference in the function
    cv::XMLParser::parse at modules/core/src/persistence.cpp. (CVE-2019-14493)

  - An issue was discovered in OpenCV 4.1.0. There is a divide-by-zero error in
    cv::HOGDescriptor::getDescriptorSize in modules/objdetect/src/hog.cpp. (CVE-2019-15939)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=886282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/opencv");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2799");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2016-1516");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-1000450");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12601");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12603");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12604");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12605");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12606");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12862");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12863");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12864");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-17760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5268");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5269");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14493");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-15939");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/opencv");
  script_set_attribute(attribute:"solution", value:
"Upgrade the opencv packages.

For Debian 9 stretch, these problems have been fixed in version 2.4.9.1+dfsg1-2+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12864");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcv-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcv2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcvaux-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcvaux2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhighgui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhighgui2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-calib3d-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-calib3d2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-contrib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-contrib2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-core2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-features2d-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-features2d2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-flann-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-flann2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-gpu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-gpu2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-highgui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-highgui2.4-deb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-imgproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-imgproc2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-legacy2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ml2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-objdetect-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-objdetect2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ocl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ocl2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-photo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-photo2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-stitching-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-stitching2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-superres-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-superres2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ts-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ts2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-video-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-video2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-videostab-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-videostab2.4v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv2.4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv2.4-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opencv-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opencv-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-opencv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libcv-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libcv2.4', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libcvaux-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libcvaux2.4', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libhighgui-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libhighgui2.4', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-calib3d-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-calib3d2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-contrib-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-contrib2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-core-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-core2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-features2d-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-features2d2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-flann-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-flann2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-gpu-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-gpu2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-highgui-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-highgui2.4-deb0', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-imgproc-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-imgproc2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-legacy-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-legacy2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ml-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ml2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-objdetect-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-objdetect2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ocl-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ocl2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-photo-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-photo2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-stitching-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-stitching2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-superres-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-superres2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ts-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-ts2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-video-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-video2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-videostab-dev', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv-videostab2.4v5', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv2.4-java', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'libopencv2.4-jni', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'opencv-data', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'opencv-doc', 'reference': '2.4.9.1+dfsg1-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-opencv', 'reference': '2.4.9.1+dfsg1-2+deb9u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcv-dev / libcv2.4 / libcvaux-dev / libcvaux2.4 / libhighgui-dev / etc');
}
