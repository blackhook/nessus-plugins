#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2020:1577.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157709);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2017-18005",
    "CVE-2018-4868",
    "CVE-2018-9303",
    "CVE-2018-9304",
    "CVE-2018-9305",
    "CVE-2018-9306",
    "CVE-2018-10772",
    "CVE-2018-11037",
    "CVE-2018-14338",
    "CVE-2018-17229",
    "CVE-2018-17230",
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
    "CVE-2018-20099",
    "CVE-2019-9143",
    "CVE-2019-13109",
    "CVE-2019-13111",
    "CVE-2019-13112",
    "CVE-2019-13113",
    "CVE-2019-13114",
    "CVE-2019-20421"
  );
  script_xref(name:"ALSA", value:"2020:1577");

  script_name(english:"AlmaLinux 8 : exiv2 (ALSA-2020:1577)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2020:1577 advisory.

  - Exiv2 0.26 has a Null Pointer Dereference in the Exiv2::DataValue::toLong function in value.cpp, related
    to crafted metadata in a TIFF file. (CVE-2017-18005)

  - The Exiv2::Jp2Image::readMetadata function in jp2image.cpp in Exiv2 0.26 allows remote attackers to cause
    a denial of service (excessive memory allocation) via a crafted file. (CVE-2018-4868)

  - In Exiv2 0.26, an assertion failure in BigTiffImage::readData in bigtiffimage.cpp results in an abort.
    (CVE-2018-9303)

  - In Exiv2 0.26, a divide by zero in BigTiffImage::printIFD in bigtiffimage.cpp could result in denial of
    service. (CVE-2018-9304)

  - In Exiv2 0.26, an out-of-bounds read in IptcData::printStructure in iptc.c could result in a crash or
    information leak, related to the == 0x1c case. (CVE-2018-9305)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2017-17724. Reason: This candidate is a
    reservation duplicate of CVE-2017-17724. Notes: All CVE users should reference CVE-2017-17724 instead of
    this candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2018-9306)

  - The tEXtToDataBuf function in pngimage.cpp in Exiv2 through 0.26 allows remote attackers to cause a denial
    of service (application crash) or possibly have unspecified other impact via a crafted file.
    (CVE-2018-10772)

  - In Exiv2 0.26, the Exiv2::PngImage::printStructure function in pngimage.cpp allows remote attackers to
    cause an information leak via a crafted file. (CVE-2018-11037)

  - samples/geotag.cpp in the example code of Exiv2 0.26 misuses the realpath function on POSIX platforms
    (other than Apple platforms) where glibc is not used, possibly leading to a buffer overflow.
    (CVE-2018-14338)

  - Exiv2::d2Data in types.cpp in Exiv2 v0.26 allows remote attackers to cause a denial of service (heap-based
    buffer overflow) via a crafted image file. (CVE-2018-17229)

  - Exiv2::ul2Data in types.cpp in Exiv2 v0.26 allows remote attackers to cause a denial of service (heap-
    based buffer overflow) via a crafted image file. (CVE-2018-17230)

  - An issue was discovered in Exiv2 v0.26. The function Exiv2::DataValue::copy in value.cpp has a NULL
    pointer dereference. (CVE-2018-17282)

  - CiffDirectory::readDirectory() at crwimage_int.cpp in Exiv2 0.26 has excessive stack consumption due to a
    recursive function, leading to Denial of service. (CVE-2018-17581)

  - There is an infinite loop in the Exiv2::Image::printIFDStructure function of image.cpp in Exiv2 0.27-RC1.
    A crafted input will lead to a remote denial of service attack. (CVE-2018-18915)

  - In Exiv2 0.26, Exiv2::IptcParser::decode in iptc.cpp (called from psdimage.cpp in the PSD image reader)
    may suffer from a denial of service (heap-based buffer over-read) caused by an integer overflow via a
    crafted PSD image file. (CVE-2018-19107)

  - In Exiv2 0.26, Exiv2::PsdImage::readMetadata in psdimage.cpp in the PSD image reader may suffer from a
    denial of service (infinite loop) caused by an integer overflow via a crafted PSD image file.
    (CVE-2018-19108)

  - In Exiv2 0.26 and previous versions, PngChunk::readRawProfile in pngchunk_int.cpp may cause a denial of
    service (application crash due to a heap-based buffer over-read) via a crafted PNG file. (CVE-2018-19535)

  - Exiv2::isoSpeed in easyaccess.cpp in Exiv2 v0.27-RC2 allows remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via a crafted file. (CVE-2018-19607)

  - There is a heap-based buffer over-read in the Exiv2::tEXtToDataBuf function of pngimage.cpp in Exiv2
    0.27-RC3. A crafted input will lead to a remote denial of service attack. (CVE-2018-20096)

  - There is a SEGV in Exiv2::Internal::TiffParserWorker::findPrimaryGroups of tiffimage_int.cpp in Exiv2
    0.27-RC3. A crafted input will lead to a remote denial of service attack. (CVE-2018-20097)

  - There is a heap-based buffer over-read in Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in Exiv2
    0.27-RC3. A crafted input will lead to a remote denial of service attack. (CVE-2018-20098)

  - There is an infinite loop in Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in Exiv2 0.27-RC3. A crafted
    input will lead to a remote denial of service attack. (CVE-2018-20099)

  - An issue was discovered in Exiv2 0.27. There is infinite recursion at Exiv2::Image::printTiffStructure in
    the file image.cpp. This can be triggered by a crafted file. It allows an attacker to cause Denial of
    Service (Segmentation fault) or possibly have unspecified other impact. (CVE-2019-9143)

  - An integer overflow in Exiv2 through 0.27.1 allows an attacker to cause a denial of service (SIGSEGV) via
    a crafted PNG image file, because PngImage::readMetadata mishandles a chunkLength - iccOffset subtraction.
    (CVE-2019-13109)

  - A WebPImage::decodeChunks integer overflow in Exiv2 through 0.27.1 allows an attacker to cause a denial of
    service (large heap allocation followed by a very long running loop) via a crafted WEBP image file.
    (CVE-2019-13111)

  - A PngChunk::parseChunkContent uncontrolled memory allocation in Exiv2 through 0.27.1 allows an attacker to
    cause a denial of service (crash due to an std::bad_alloc exception) via a crafted PNG image file.
    (CVE-2019-13112)

  - Exiv2 through 0.27.1 allows an attacker to cause a denial of service (crash due to assertion failure) via
    an invalid data location in a CRW image file. (CVE-2019-13113)

  - http.c in Exiv2 through 0.27.1 allows a malicious http server to cause a denial of service (crash due to a
    NULL pointer dereference) by returning a crafted response that lacks a space character. (CVE-2019-13114)

  - In Jp2Image::readMetadata() in jp2image.cpp in Exiv2 0.27.2, an input file can result in an infinite loop
    and hang, with high CPU consumption. Remote attackers could leverage this vulnerability to cause a denial
    of service via a crafted file. (CVE-2019-20421)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2020-1577.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:exiv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:exiv2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gegl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-color-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libgexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libgexiv2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'exiv2-devel-0.27.2-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exiv2-devel-0.27.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exiv2-doc-0.27.2-5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gegl-0.2.0-39.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gegl-0.2.0-39.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-color-manager-3.28.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgexiv2-0.10.8-4.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgexiv2-0.10.8-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgexiv2-devel-0.10.8-4.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgexiv2-devel-0.10.8-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exiv2-devel / exiv2-doc / gegl / gnome-color-manager / libgexiv2 / etc');
}
