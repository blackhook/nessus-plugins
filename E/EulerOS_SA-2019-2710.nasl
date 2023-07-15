#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132377);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-11683",
    "CVE-2017-14859",
    "CVE-2017-14862",
    "CVE-2017-14864",
    "CVE-2017-14865",
    "CVE-2017-17669",
    "CVE-2017-18005",
    "CVE-2018-16336",
    "CVE-2018-4868",
    "CVE-2019-14982"
  );

  script_name(english:"EulerOS 2.0 SP5 : exiv2 (EulerOS-SA-2019-2710)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the exiv2 package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - Exiv2::Internal::PngChunk::parseTXTChunk in Exiv2 v0.26
    allows remote attackers to cause a denial of service
    (heap-based buffer over-read) via a crafted image file,
    a different vulnerability than
    CVE-2018-10999.(CVE-2018-16336)

  - The Exiv2::Jp2Image::readMetadata function in
    jp2image.cpp in Exiv2 0.26 allows remote attackers to
    cause a denial of service (excessive memory allocation)
    via a crafted file.(CVE-2018-4868)

  - In Exiv2 before v0.27.2, there is an integer overflow
    vulnerability in the WebPImage::getHeaderOffset
    function in webpimage.cpp. It can lead to a buffer
    overflow vulnerability and a crash.(CVE-2019-14982)

  - There is a reachable assertion in the
    Internal::TiffReader::visitDirectory function in
    tiffvisitor.cpp of Exiv2 0.26 that will lead to a
    remote denial of service attack via crafted
    input.(CVE-2017-11683)

  - An Invalid memory address dereference was discovered in
    Exiv2::StringValueBase::read in value.cpp in Exiv2
    0.26. The vulnerability causes a segmentation fault and
    application crash, which leads to denial of
    service.(CVE-2017-14859)

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

  - There is a heap-based buffer overflow in the
    Exiv2::us2Data function of types.cpp in Exiv2 0.26. A
    Crafted input will lead to a denial of service
    attack.(CVE-2017-14865)

  - There is a heap-based buffer over-read in the
    Exiv2::Internal::PngChunk::keyTXTChunk function of
    pngchunk_int.cpp in Exiv2 0.26. A crafted PNG file will
    lead to a remote denial of service
    attack.(CVE-2017-17669)

  - Exiv2 0.26 has a Null Pointer Dereference in the
    Exiv2::DataValue::toLong function in value.cpp, related
    to crafted metadata in a TIFF file.(CVE-2017-18005)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2710
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed6f2a44");
  script_set_attribute(attribute:"solution", value:
"Update the affected exiv2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14982");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/23");

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

pkgs = ["exiv2-libs-0.26-3.h10.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
