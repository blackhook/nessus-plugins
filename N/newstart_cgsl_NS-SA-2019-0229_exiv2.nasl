#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0229. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132507);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-17724",
    "CVE-2018-8976",
    "CVE-2018-8977",
    "CVE-2018-9305",
    "CVE-2018-10772",
    "CVE-2018-10958",
    "CVE-2018-10998",
    "CVE-2018-10999",
    "CVE-2018-11037",
    "CVE-2018-12264",
    "CVE-2018-12265",
    "CVE-2018-14046",
    "CVE-2018-17282",
    "CVE-2018-17581",
    "CVE-2018-18915",
    "CVE-2018-19107",
    "CVE-2018-19108",
    "CVE-2018-19535",
    "CVE-2018-19607",
    "CVE-2018-20096",
    "CVE-2018-20097",
    "CVE-2018-20098",
    "CVE-2018-20099"
  );
  script_bugtraq_id(106003, 109287, 109292);

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : exiv2 Multiple Vulnerabilities (NS-SA-2019-0229)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has exiv2 packages installed that are affected by
multiple vulnerabilities:

  - In Exiv2 0.26, an out-of-bounds read in
    IptcData::printStructure in iptc.c could result in a
    crash or information leak, related to the == 0x1c
    case. (CVE-2018-9305)

  - In Exiv2 0.26, there is a heap-based buffer over-read in
    the Exiv2::IptcData::printStructure function in
    iptc.cpp, related to the != 0x1c case. Remote
    attackers can exploit this vulnerability to cause a
    denial of service via a crafted TIFF file.
    (CVE-2017-17724)

  - An issue was discovered in Exiv2 v0.26. The function
    Exiv2::DataValue::copy in value.cpp has a NULL pointer
    dereference. (CVE-2018-17282)

  - There is an infinite loop in the
    Exiv2::Image::printIFDStructure function of image.cpp in
    Exiv2 0.27-RC1. A crafted input will lead to a remote
    denial of service attack. (CVE-2018-18915)

  - CiffDirectory::readDirectory() at crwimage_int.cpp in
    Exiv2 0.26 has excessive stack consumption due to a
    recursive function, leading to Denial of service.
    (CVE-2018-17581)

  - In Exiv2 0.26, Exiv2::IptcParser::decode in iptc.cpp
    (called from psdimage.cpp in the PSD image reader) may
    suffer from a denial of service (heap-based buffer over-
    read) caused by an integer overflow via a crafted PSD
    image file. (CVE-2018-19107)

  - In Exiv2 0.26, Exiv2::PsdImage::readMetadata in
    psdimage.cpp in the PSD image reader may suffer from a
    denial of service (infinite loop) caused by an integer
    overflow via a crafted PSD image file. (CVE-2018-19108)

  - In Exiv2 0.26 and previous versions,
    PngChunk::readRawProfile in pngchunk_int.cpp may cause a
    denial of service (application crash due to a heap-based
    buffer over-read) via a crafted PNG file.
    (CVE-2018-19535)

  - Exiv2::isoSpeed in easyaccess.cpp in Exiv2 v0.27-RC2
    allows remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via a
    crafted file. (CVE-2018-19607)

  - There is a SEGV in
    Exiv2::Internal::TiffParserWorker::findPrimaryGroups of
    tiffimage_int.cpp in Exiv2 0.27-RC3. A crafted input
    will lead to a remote denial of service attack.
    (CVE-2018-20097)

  - There is an infinite loop in
    Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in
    Exiv2 0.27-RC3. A crafted input will lead to a remote
    denial of service attack. (CVE-2018-20099)

  - Exiv2 0.26 has integer overflows in
    LoaderTiff::getData() in preview.cpp, leading to an out-
    of-bounds read in Exiv2::ValueType::setDataArea in
    value.hpp. (CVE-2018-12264)

  - Exiv2 0.26 has an integer overflow in the LoaderExifJpeg
    class in preview.cpp, leading to an out-of-bounds read
    in Exiv2::MemIo::read in basicio.cpp. (CVE-2018-12265)

  - In types.cpp in Exiv2 0.26, a large size value may lead
    to a SIGABRT during an attempt at memory allocation for
    an Exiv2::Internal::PngChunk::zlibUncompress call.
    (CVE-2018-10958)

  - An issue was discovered in Exiv2 0.26. readMetadata in
    jp2image.cpp allows remote attackers to cause a denial
    of service (SIGABRT) by triggering an incorrect
    Safe::add call. (CVE-2018-10998)

  - The tEXtToDataBuf function in pngimage.cpp in Exiv2
    through 0.26 allows remote attackers to cause a denial
    of service (application crash) or possibly have
    unspecified other impact via a crafted file.
    (CVE-2018-10772)

  - In Exiv2 0.26, jpgimage.cpp allows remote attackers to
    cause a denial of service (image.cpp
    Exiv2::Internal::stringFormat out-of-bounds read) via a
    crafted file. (CVE-2018-8976)

  - In Exiv2 0.26, the Exiv2::Internal::printCsLensFFFF
    function in canonmn_int.cpp allows remote attackers to
    cause a denial of service (invalid memory access) via a
    crafted file. (CVE-2018-8977)

  - Exiv2 0.26 has a heap-based buffer over-read in
    WebPImage::decodeChunks in webpimage.cpp.
    (CVE-2018-14046)

  - In Exiv2 0.26, the Exiv2::PngImage::printStructure
    function in pngimage.cpp allows remote attackers to
    cause an information leak via a crafted file.
    (CVE-2018-11037)

  - There is a heap-based buffer over-read in the
    Exiv2::tEXtToDataBuf function of pngimage.cpp in Exiv2
    0.27-RC3. A crafted input will lead to a remote denial
    of service attack. (CVE-2018-20096)

  - There is a heap-based buffer over-read in
    Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in
    Exiv2 0.27-RC3. A crafted input will lead to a remote
    denial of service attack. (CVE-2018-20098)

  - An issue was discovered in Exiv2 0.26. The
    Exiv2::Internal::PngChunk::parseTXTChunk function has a
    heap-based buffer over-read. (CVE-2018-10999)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0229");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL exiv2 packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14046");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "exiv2-0.27.0-2.el7_6",
    "exiv2-debuginfo-0.27.0-2.el7_6",
    "exiv2-devel-0.27.0-2.el7_6",
    "exiv2-doc-0.27.0-2.el7_6",
    "exiv2-libs-0.27.0-2.el7_6"
  ],
  "CGSL MAIN 5.05": [
    "exiv2-0.27.0-2.el7_6",
    "exiv2-debuginfo-0.27.0-2.el7_6",
    "exiv2-devel-0.27.0-2.el7_6",
    "exiv2-doc-0.27.0-2.el7_6",
    "exiv2-libs-0.27.0-2.el7_6"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exiv2");
}
