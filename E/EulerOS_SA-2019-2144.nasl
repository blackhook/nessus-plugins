#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130853);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-1000126",
    "CVE-2017-17723",
    "CVE-2018-10958",
    "CVE-2018-10998",
    "CVE-2018-10999",
    "CVE-2018-11531",
    "CVE-2018-14046",
    "CVE-2018-17282",
    "CVE-2018-17581",
    "CVE-2018-19107",
    "CVE-2018-19108",
    "CVE-2018-19535",
    "CVE-2018-20096",
    "CVE-2018-20098",
    "CVE-2018-20099",
    "CVE-2019-13112"
  );

  script_name(english:"EulerOS 2.0 SP5 : exiv2 (EulerOS-SA-2019-2144)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the exiv2 package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - Exiv2 0.26 has a heap-based buffer over-read in
    WebPImage::decodeChunks in
    webpimage.cpp.(CVE-2018-14046)

  - There is a heap-based buffer over-read in the
    Exiv2::tEXtToDataBuf function of pngimage.cpp in Exiv2
    0.27-RC3. A crafted input will lead to a remote denial
    of service attack.(CVE-2018-20096)

  - There is a heap-based buffer over-read in
    Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in
    Exiv2 0.27-RC3. A crafted input will lead to a remote
    denial of service attack.(CVE-2018-20098)

  - There is an infinite loop in
    Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in
    Exiv2 0.27-RC3. A crafted input will lead to a remote
    denial of service attack.(CVE-2018-20099)

  - A PngChunk::parseChunkContent uncontrolled memory
    allocation in Exiv2 through 0.27.1 allows an attacker
    to cause a denial of service (crash due to an
    std::bad_alloc exception) via a crafted PNG image
    file.(CVE-2019-13112)

  - CiffDirectory::readDirectory() at crwimage_int.cpp in
    Exiv2 0.26 has excessive stack consumption due to a
    recursive function, leading to Denial of
    service.(CVE-2018-17581)

  - In Exiv2 0.26 and previous versions,
    PngChunk::readRawProfile in pngchunk_int.cpp may cause
    a denial of service (application crash due to a
    heap-based buffer over-read) via a crafted PNG
    file.(CVE-2018-19535)

  - In types.cpp in Exiv2 0.26, a large size value may lead
    to a SIGABRT during an attempt at memory allocation for
    an Exiv2::Internal::PngChunk::zlibUncompress
    call.(CVE-2018-10958)

  - An issue was discovered in Exiv2 0.26. readMetadata in
    jp2image.cpp allows remote attackers to cause a denial
    of service (SIGABRT) by triggering an incorrect
    Safe::add call.(CVE-2018-10998)

  - An issue was discovered in Exiv2 0.26. The
    Exiv2::Internal::PngChunk::parseTXTChunk function has a
    heap-based buffer over-read.(CVE-2018-10999)

  - In Exiv2 0.26, Exiv2::PsdImage::readMetadata in
    psdimage.cpp in the PSD image reader may suffer from a
    denial of service (infinite loop) caused by an integer
    overflow via a crafted PSD image file.(CVE-2018-19108)

  - In Exiv2 0.26, Exiv2::IptcParser::decode in iptc.cpp
    (called from psdimage.cpp in the PSD image reader) may
    suffer from a denial of service (heap-based buffer
    over-read) caused by an integer overflow via a crafted
    PSD image file.(CVE-2018-19107)

  - An issue was discovered in Exiv2 v0.26. The function
    Exiv2::DataValue::copy in value.cpp has a NULL pointer
    dereference.(CVE-2018-17282)

  - exiv2 0.26 contains a Stack out of bounds read in webp
    parser(CVE-2017-1000126)

  - In Exiv2 0.26, there is a heap-based buffer over-read
    in the Exiv2::Image::byteSwap4 function in image.cpp.
    Remote attackers can exploit this vulnerability to
    disclose memory data or cause a denial of service via a
    crafted TIFF file.(CVE-2017-17723)

  - Exiv2 0.26 has a heap-based buffer overflow in getData
    in preview.cpp.(CVE-2018-11531)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2144
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1da418ef");
  script_set_attribute(attribute:"solution", value:
"Update the affected exiv2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:exiv2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["exiv2-libs-0.26-3.h9.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
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
