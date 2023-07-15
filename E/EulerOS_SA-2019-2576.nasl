#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132293);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-11591",
    "CVE-2017-11683",
    "CVE-2017-14859",
    "CVE-2017-14862",
    "CVE-2017-14864",
    "CVE-2017-17669",
    "CVE-2017-18005",
    "CVE-2017-9239",
    "CVE-2018-10958",
    "CVE-2018-10998",
    "CVE-2018-10999",
    "CVE-2018-17581",
    "CVE-2018-19107",
    "CVE-2018-19108",
    "CVE-2018-19535",
    "CVE-2018-20097",
    "CVE-2019-13112",
    "CVE-2019-13113"
  );

  script_name(english:"EulerOS 2.0 SP3 : exiv2 (EulerOS-SA-2019-2576)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the exiv2 package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - A PngChunk::parseChunkContent uncontrolled memory
    allocation in Exiv2 through 0.27.1 allows an attacker
    to cause a denial of service (crash due to an
    std::bad_alloc exception) via a crafted PNG image
    file.(CVE-2019-13112)

  - An Invalid memory address dereference was discovered in
    Exiv2::DataValue::read in value.cpp in Exiv2 0.26. The
    vulnerability causes a segmentation fault and
    application crash, which leads to denial of
    service.(CVE-2017-14862)

  - An Invalid memory address dereference was discovered in
    Exiv2::getULong in types.cpp in Exiv2 0.26. The
    vulnerability causes a segmentation fault and
    application crash, which leads to denial of
    service.(CVE-2017-14864)

  - An Invalid memory address dereference was discovered in
    Exiv2::StringValueBase::read in value.cpp in Exiv2
    0.26. The vulnerability causes a segmentation fault and
    application crash, which leads to denial of
    service.(CVE-2017-14859)

  - An issue was discovered in Exiv2 0.26. readMetadata in
    jp2image.cpp allows remote attackers to cause a denial
    of service (SIGABRT) by triggering an incorrect
    Safe::add call.(CVE-2018-10998)

  - An issue was discovered in Exiv2 0.26. The
    Exiv2::Internal::PngChunk::parseTXTChunk function has a
    heap-based buffer over-read.(CVE-2018-10999)

  - An issue was discovered in Exiv2 0.26. When the data
    structure of the structure ifd is incorrect, the
    program assigns pValue_ to 0x0, and the value of
    pValue() is 0x0. TiffImageEntry::doWriteImage will use
    the value of pValue() to cause a segmentation fault. To
    exploit this vulnerability, someone must open a crafted
    tiff file.(CVE-2017-9239)

  - CiffDirectory::readDirectory() at crwimage_int.cpp in
    Exiv2 0.26 has excessive stack consumption due to a
    recursive function, leading to Denial of
    service.(CVE-2018-17581)

  - Exiv2 0.26 has a Null Pointer Dereference in the
    Exiv2::DataValue::toLong function in value.cpp, related
    to crafted metadata in a TIFF file.(CVE-2017-18005)

  - Exiv2 through 0.27.1 allows an attacker to cause a
    denial of service (crash due to assertion failure) via
    an invalid data location in a CRW image
    file.(CVE-2019-13113)

  - In Exiv2 0.26 and previous versions,
    PngChunk::readRawProfile in pngchunk_int.cpp may cause
    a denial of service (application crash due to a
    heap-based buffer over-read) via a crafted PNG
    file.(CVE-2018-19535)

  - In Exiv2 0.26, Exiv2::IptcParser::decode in iptc.cpp
    (called from psdimage.cpp in the PSD image reader) may
    suffer from a denial of service (heap-based buffer
    over-read) caused by an integer overflow via a crafted
    PSD image file.(CVE-2018-19107)

  - In Exiv2 0.26, Exiv2::PsdImage::readMetadata in
    psdimage.cpp in the PSD image reader may suffer from a
    denial of service (infinite loop) caused by an integer
    overflow via a crafted PSD image file.(CVE-2018-19108)

  - In types.cpp in Exiv2 0.26, a large size value may lead
    to a SIGABRT during an attempt at memory allocation for
    an Exiv2::Internal::PngChunk::zlibUncompress
    call.(CVE-2018-10958)

  - There is a Floating point exception in the
    Exiv2::ValueType function in Exiv2 0.26 that will lead
    to a remote denial of service attack via crafted
    input.(CVE-2017-11591)

  - There is a heap-based buffer over-read in the
    Exiv2::Internal::PngChunk::keyTXTChunk function of
    pngchunk_int.cpp in Exiv2 0.26. A crafted PNG file will
    lead to a remote denial of service
    attack.(CVE-2017-17669)

  - There is a reachable assertion in the
    Internal::TiffReader::visitDirectory function in
    tiffvisitor.cpp of Exiv2 0.26 that will lead to a
    remote denial of service attack via crafted
    input.(CVE-2017-11683)

  - There is a SEGV in
    Exiv2::Internal::TiffParserWorker::findPrimaryGroups of
    tiffimage_int.cpp in Exiv2 0.27-RC3. A crafted input
    will lead to a remote denial of service
    attack.(CVE-2018-20097)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2576
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7596ecd");
  script_set_attribute(attribute:"solution", value:
"Update the affected exiv2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["exiv2-libs-0.23-6.h7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
