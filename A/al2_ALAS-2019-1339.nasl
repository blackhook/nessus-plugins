#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1339.
#

include("compat.inc");

if (description)
{
  script_id(130235);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/18");

  script_cve_id("CVE-2017-17724", "CVE-2018-10772", "CVE-2018-10958", "CVE-2018-10998", "CVE-2018-11037", "CVE-2018-12264", "CVE-2018-12265", "CVE-2018-14046", "CVE-2018-17282", "CVE-2018-17581", "CVE-2018-18915", "CVE-2018-19107", "CVE-2018-19108", "CVE-2018-19535", "CVE-2018-19607", "CVE-2018-20096", "CVE-2018-20097", "CVE-2018-20098", "CVE-2018-20099", "CVE-2018-8976", "CVE-2018-8977", "CVE-2018-9305");
  script_xref(name:"ALAS", value:"2019-1339");

  script_name(english:"Amazon Linux 2 : exiv2 (ALAS-2019-1339)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer underflow, leading to heap-based out-of-bound read, was
found in the way Exiv2 library prints IPTC Photo Metadata embedded in
an image. By persuading a victim to open a crafted image, a remote
attacker could crash the application or possibly retrieve a portion of
memory.(CVE-2017-17724)

The tEXtToDataBuf function in pngimage.cpp in Exiv2 through 0.26
allows remote attackers to cause a denial of service (application
crash) or possibly have unspecified other impact via a crafted
file.(CVE-2018-10772)

In types.cpp in Exiv2 0.26, a large size value may lead to a SIGABRT
during an attempt at memory allocation for an
Exiv2::Internal::PngChunk::zlibUncompress call.(CVE-2018-10958)

An issue was discovered in Exiv2 0.26. readMetadata in jp2image.cpp
allows remote attackers to cause a denial of service (SIGABRT) by
triggering an incorrect Safe::add call.(CVE-2018-10998)

In Exiv2 0.26, the Exiv2::PngImage::printStructure function in
pngimage.cpp allows remote attackers to cause an information leak via
a crafted file.(CVE-2018-11037)

Exiv2 0.26 has integer overflows in LoaderTiff::getData() in
preview.cpp, leading to an out-of-bounds read in
Exiv2::ValueType::setDataArea in value.hpp.(CVE-2018-12264)

Exiv2 0.26 has an integer overflow in the LoaderExifJpeg class in
preview.cpp, leading to an out-of-bounds read in Exiv2::MemIo::read in
basicio.cpp.(CVE-2018-12265)

Exiv2 0.26 has a heap-based buffer over-read in
WebPImage::decodeChunks in webpimage.cpp.(CVE-2018-14046)

An issue was discovered in Exiv2 v0.26. The function
Exiv2::DataValue::copy in value.cpp has a NULL pointer
dereference.(CVE-2018-17282)

CiffDirectory::readDirectory() at crwimage_int.cpp in Exiv2 0.26 has
excessive stack consumption due to a recursive function, leading to
Denial of service.(CVE-2018-17581)

There is an infinite loop in the Exiv2::Image::printIFDStructure
function of image.cpp in Exiv2 0.27-RC1. A crafted input will lead to
a remote denial of service attack.(CVE-2018-18915)

In Exiv2 0.26, Exiv2::IptcParser::decode in iptc.cpp (called from
psdimage.cpp in the PSD image reader) may suffer from a denial of
service (heap-based buffer over-read) caused by an integer overflow
via a crafted PSD image file.(CVE-2018-19107)

In Exiv2 0.26, Exiv2::PsdImage::readMetadata in psdimage.cpp in the
PSD image reader may suffer from a denial of service (infinite loop)
caused by an integer overflow via a crafted PSD image
file.(CVE-2018-19108)

In Exiv2 0.26 and previous versions, PngChunk::readRawProfile in
pngchunk_int.cpp may cause a denial of service (application crash due
to a heap-based buffer over-read) via a crafted PNG
file.(CVE-2018-19535)

Exiv2::isoSpeed in easyaccess.cpp in Exiv2 v0.27-RC2 allows remote
attackers to cause a denial of service (NULL pointer dereference and
application crash) via a crafted file.(CVE-2018-19607)

There is a heap-based buffer over-read in the Exiv2::tEXtToDataBuf
function of pngimage.cpp in Exiv2 0.27-RC3. A crafted input will lead
to a remote denial of service attack.(CVE-2018-20096)

There is a SEGV in
Exiv2::Internal::TiffParserWorker::findPrimaryGroups of
tiffimage_int.cpp in Exiv2 0.27-RC3. A crafted input will lead to a
remote denial of service attack.(CVE-2018-20097)

There is a heap-based buffer over-read in
Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in Exiv2 0.27-RC3. A
crafted input will lead to a remote denial of service
attack.(CVE-2018-20098)

There is an infinite loop in Exiv2::Jp2Image::encodeJp2Header of
jp2image.cpp in Exiv2 0.27-RC3. A crafted input will lead to a remote
denial of service attack.(CVE-2018-20099)

In Exiv2 0.26, jpgimage.cpp allows remote attackers to cause a denial
of service (image.cpp Exiv2::Internal::stringFormat out-of-bounds
read) via a crafted file.(CVE-2018-8976)

In Exiv2 0.26, the Exiv2::Internal::printCsLensFFFF function in
canonmn_int.cpp allows remote attackers to cause a denial of service
(invalid memory access) via a crafted file.(CVE-2018-8977)

An out-of-bounds read vulnerability has been discovered in
IptcData::printStructure in iptc.cpp file of Exiv2 0.26. An attacker
could cause a crash or an information leak by providing a crafted
image.(CVE-2018-9305)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1339.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update exiv2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exiv2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exiv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exiv2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exiv2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"exiv2-0.27.0-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"exiv2-debuginfo-0.27.0-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"exiv2-devel-0.27.0-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"exiv2-doc-0.27.0-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"exiv2-libs-0.27.0-3.amzn2.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exiv2 / exiv2-debuginfo / exiv2-devel / exiv2-doc / exiv2-libs");
}
