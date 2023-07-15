##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:1577. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145828);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/23");

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
  script_bugtraq_id(
    102477,
    104607,
    106003,
    107161,
    109279,
    109287,
    109292
  );
  script_xref(name:"RHSA", value:"2020:1577");

  script_name(english:"CentOS 8 : exiv2 (CESA-2020:1577)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:1577 advisory.

  - exiv2: null pointer dereference in the Exiv2::DataValue::toLong function in value.cpp (CVE-2017-18005)

  - exiv2: OOB read in pngimage.cpp:tEXtToDataBuf() allows for crash via crafted file (CVE-2018-10772)

  - exiv2: information leak via a crafted file (CVE-2018-11037)

  - exiv2: buffer overflow in samples/geotag.cpp (CVE-2018-14338)

  - exiv2: heap-based buffer overflow in Exiv2::d2Data in types.cpp (CVE-2018-17229)

  - exiv2: heap-based buffer overflow in Exiv2::ul2Data in types.cpp (CVE-2018-17230)

  - exiv2: NULL pointer dereference in Exiv2::DataValue::copy in value.cpp leading to application crash
    (CVE-2018-17282)

  - exiv2: Stack overflow in CiffDirectory::readDirectory() at crwimage_int.cpp leading to denial of service
    (CVE-2018-17581)

  - exiv2: infinite loop in Exiv2::Image::printIFDStructure function in image.cpp (CVE-2018-18915)

  - exiv2: heap-based buffer over-read in Exiv2::IptcParser::decode in iptc.cpp (CVE-2018-19107)

  - exiv2: infinite loop in Exiv2::PsdImage::readMetadata in psdimage.cpp (CVE-2018-19108)

  - exiv2: heap-based buffer over-read in PngChunk::readRawProfile in pngchunk_int.cpp (CVE-2018-19535)

  - exiv2: NULL pointer dereference in Exiv2::isoSpeed in easyaccess.cpp (CVE-2018-19607)

  - exiv2: Heap-based buffer over-read in Exiv2::tEXtToDataBuf function resulting in a denial of service
    (CVE-2018-20096)

  - exiv2: Segmentation fault in Exiv2::Internal::TiffParserWorker::findPrimaryGroups function
    (CVE-2018-20097)

  - exiv2: Heap-based buffer over-read in Exiv2::Jp2Image::encodeJp2Header resulting in a denial of service
    (CVE-2018-20098)

  - exiv2: Infinite loop in Exiv2::Jp2Image::encodeJp2Header resulting in a denial of service (CVE-2018-20099)

  - exiv2: Excessive memory allocation in Exiv2::Jp2Image::readMetadata function in jp2image.cpp
    (CVE-2018-4868)

  - exiv2: assertion failure in BigTiffImage::readData in bigtiffimage.cpp (CVE-2018-9303)

  - exiv2: divide by zero in BigTiffImage::printIFD in bigtiffimage.cpp (CVE-2018-9304)

  - exiv2: out of bounds read in IptcData::printStructure in iptc.c (CVE-2018-9305, CVE-2018-9306)

  - exiv2: denial of service in PngImage::readMetadata (CVE-2019-13109)

  - exiv2: integer overflow in WebPImage::decodeChunks leads to denial of service (CVE-2019-13111)

  - exiv2: uncontrolled memory allocation in PngChunk::parseChunkContent causing denial of service
    (CVE-2019-13112)

  - exiv2: invalid data location in CRW image file causing denial of service (CVE-2019-13113)

  - exiv2: null-pointer dereference in http.c causing denial of service (CVE-2019-13114)

  - exiv2: infinite loop and hang in Jp2Image::readMetadata() in jp2image.cpp could lead to DoS
    (CVE-2019-20421)

  - exiv2: infinite recursion in Exiv2::Image::printTiffStructure in file image.cpp resulting in denial of
    service (CVE-2019-9143)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1577");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gegl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-color-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgexiv2-devel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'exiv2-0.27.2-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exiv2-0.27.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exiv2-devel-0.27.2-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exiv2-devel-0.27.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exiv2-doc-0.27.2-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exiv2-doc-0.27.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exiv2-libs-0.27.2-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exiv2-libs-0.27.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gegl-0.2.0-39.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gegl-0.2.0-39.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-color-manager-3.28.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-color-manager-3.28.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgexiv2-0.10.8-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgexiv2-0.10.8-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgexiv2-devel-0.10.8-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgexiv2-devel-0.10.8-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exiv2 / exiv2-devel / exiv2-doc / exiv2-libs / gegl / etc');
}
