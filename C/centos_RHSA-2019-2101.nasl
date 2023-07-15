#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2101 and 
# CentOS Errata and Security Advisory 2019:2101 respectively.
#

include("compat.inc");

if (description)
{
  script_id(129015);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2017-17724", "CVE-2018-10772", "CVE-2018-10958", "CVE-2018-10998", "CVE-2018-10999", "CVE-2018-11037", "CVE-2018-12264", "CVE-2018-12265", "CVE-2018-14046", "CVE-2018-17282", "CVE-2018-17581", "CVE-2018-18915", "CVE-2018-19107", "CVE-2018-19108", "CVE-2018-19535", "CVE-2018-19607", "CVE-2018-20096", "CVE-2018-20097", "CVE-2018-20098", "CVE-2018-20099", "CVE-2018-8976", "CVE-2018-8977", "CVE-2018-9305");
  script_xref(name:"RHSA", value:"2019:2101");

  script_name(english:"CentOS 7 : exiv2 (CESA-2019:2101)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for exiv2 is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The exiv2 packages provide a command line utility which can display
and manipulate image metadata such as EXIF, LPTC, and JPEG comments.

The following packages have been upgraded to a later upstream version:
exiv2 (0.27.0). (BZ#1652637)

Security Fix(es) :

* exiv2: heap-buffer-overflow in Exiv2::IptcData::printStructure in
src/ iptc.cpp (CVE-2017-17724)

* exiv2: out-of-bounds read in Exiv2::Internal::stringFormat image.cpp
(CVE-2018-8976)

* exiv2: invalid memory access in Exiv2::Internal::printCsLensFFFF
function in canonmn_int.cpp (CVE-2018-8977)

* exiv2: out of bounds read in IptcData::printStructure in iptc.c
(CVE-2018-9305)

* exiv2: OOB read in pngimage.cpp:tEXtToDataBuf() allows for crash via
crafted file (CVE-2018-10772)

* exiv2: SIGABRT caused by memory allocation in
types.cpp:Exiv2::Internal::PngChunk::zlibUncompress() (CVE-2018-10958)

* exiv2: SIGABRT by triggering an incorrect Safe::add call
(CVE-2018-10998)

* exiv2: information leak via a crafted file (CVE-2018-11037)

* exiv2: integer overflow in getData function in preview.cpp
(CVE-2018-12264)

* exiv2: integer overflow in the LoaderExifJpeg class in preview.cpp
(CVE-2018-12265)

* exiv2: heap-based buffer over-read in WebPImage::decodeChunks in
webpimage.cpp (CVE-2018-14046)

* exiv2: NULL pointer dereference in Exiv2::DataValue::copy in
value.cpp leading to application crash (CVE-2018-17282)

* exiv2: Stack overflow in CiffDirectory::readDirectory() at
crwimage_int.cpp leading to denial of service (CVE-2018-17581)

* exiv2: infinite loop in Exiv2::Image::printIFDStructure function in
image.cpp (CVE-2018-18915)

* exiv2: heap-based buffer over-read in Exiv2::IptcParser::decode in
iptc.cpp (CVE-2018-19107)

* exiv2: infinite loop in Exiv2::PsdImage::readMetadata in
psdimage.cpp (CVE-2018-19108)

* exiv2: heap-based buffer over-read in PngChunk::readRawProfile in
pngchunk_int.cpp (CVE-2018-19535)

* exiv2: NULL pointer dereference in Exiv2::isoSpeed in easyaccess.cpp
(CVE-2018-19607)

* exiv2: Heap-based buffer over-read in Exiv2::tEXtToDataBuf function
resulting in a denial of service (CVE-2018-20096)

* exiv2: Segmentation fault in
Exiv2::Internal::TiffParserWorker::findPrimaryGroups function
(CVE-2018-20097)

* exiv2: Heap-based buffer over-read in
Exiv2::Jp2Image::encodeJp2Header resulting in a denial of service
(CVE-2018-20098)

* exiv2: Infinite loop in Exiv2::Jp2Image::encodeJp2Header resulting
in a denial of service (CVE-2018-20099)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-announce/2019-September/023446.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa84d62a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected exiv2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12264");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"exiv2-0.27.0-2.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"exiv2-devel-0.27.0-2.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"exiv2-doc-0.27.0-2.el7_6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"exiv2-libs-0.27.0-2.el7_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exiv2 / exiv2-devel / exiv2-doc / exiv2-libs");
}
