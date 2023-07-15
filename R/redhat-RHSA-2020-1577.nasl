##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1577. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143032);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

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

  script_name(english:"RHEL 8 : exiv2 (RHSA-2020:1577)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1577 advisory.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-18005");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-4868");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-9303");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-9304");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-9305");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-9306");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-10772");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-11037");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14338");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-17229");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-17230");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-17282");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-17581");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-18915");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19107");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19108");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19535");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-19607");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20096");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20097");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20098");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20099");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9143");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13109");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13111");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13112");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13113");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13114");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20421");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1531171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1531724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1566725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1566731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1566735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1566737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1579544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1594627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1609396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1632481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1632484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1632490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1635045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1646555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1649094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1649101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1656187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1656195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1660423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1660424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1660425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1660426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1684381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1800472");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 122, 125, 190, 200, 369, 400, 476, 617, 835);

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exiv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exiv2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exiv2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gegl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-color-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgexiv2-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.2/x86_64/appstream/debug',
      'content/aus/rhel8/8.2/x86_64/appstream/os',
      'content/aus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.2/x86_64/baseos/debug',
      'content/aus/rhel8/8.2/x86_64/baseos/os',
      'content/aus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.2/ppc64le/appstream/os',
      'content/e4s/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.2/ppc64le/baseos/os',
      'content/e4s/rhel8/8.2/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sap/debug',
      'content/e4s/rhel8/8.2/ppc64le/sap/os',
      'content/e4s/rhel8/8.2/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/appstream/debug',
      'content/e4s/rhel8/8.2/x86_64/appstream/os',
      'content/e4s/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/baseos/debug',
      'content/e4s/rhel8/8.2/x86_64/baseos/os',
      'content/e4s/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.2/x86_64/highavailability/os',
      'content/e4s/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sap/debug',
      'content/e4s/rhel8/8.2/x86_64/sap/os',
      'content/e4s/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/appstream/debug',
      'content/eus/rhel8/8.2/ppc64le/appstream/os',
      'content/eus/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/baseos/debug',
      'content/eus/rhel8/8.2/ppc64le/baseos/os',
      'content/eus/rhel8/8.2/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.2/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.2/ppc64le/highavailability/os',
      'content/eus/rhel8/8.2/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.2/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.2/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sap/debug',
      'content/eus/rhel8/8.2/ppc64le/sap/os',
      'content/eus/rhel8/8.2/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.2/ppc64le/supplementary/os',
      'content/eus/rhel8/8.2/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/appstream/debug',
      'content/eus/rhel8/8.2/x86_64/appstream/os',
      'content/eus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/baseos/debug',
      'content/eus/rhel8/8.2/x86_64/baseos/os',
      'content/eus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.2/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/highavailability/debug',
      'content/eus/rhel8/8.2/x86_64/highavailability/os',
      'content/eus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.2/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sap/debug',
      'content/eus/rhel8/8.2/x86_64/sap/os',
      'content/eus/rhel8/8.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/supplementary/debug',
      'content/eus/rhel8/8.2/x86_64/supplementary/os',
      'content/eus/rhel8/8.2/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/appstream/debug',
      'content/tus/rhel8/8.2/x86_64/appstream/os',
      'content/tus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/baseos/debug',
      'content/tus/rhel8/8.2/x86_64/baseos/os',
      'content/tus/rhel8/8.2/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/highavailability/debug',
      'content/tus/rhel8/8.2/x86_64/highavailability/os',
      'content/tus/rhel8/8.2/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/nfv/debug',
      'content/tus/rhel8/8.2/x86_64/nfv/os',
      'content/tus/rhel8/8.2/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/rt/debug',
      'content/tus/rhel8/8.2/x86_64/rt/os',
      'content/tus/rhel8/8.2/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'exiv2-0.27.2-5.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-devel-0.27.2-5.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-doc-0.27.2-5.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-libs-0.27.2-5.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gegl-0.2.0-39.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-color-manager-3.28.0-3.el8', 'sp':'2', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-color-manager-3.28.0-3.el8', 'sp':'2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgexiv2-0.10.8-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgexiv2-devel-0.10.8-4.el8', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.4/x86_64/appstream/debug',
      'content/aus/rhel8/8.4/x86_64/appstream/os',
      'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.4/x86_64/baseos/debug',
      'content/aus/rhel8/8.4/x86_64/baseos/os',
      'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.4/ppc64le/appstream/os',
      'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.4/ppc64le/baseos/os',
      'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sap/debug',
      'content/e4s/rhel8/8.4/ppc64le/sap/os',
      'content/e4s/rhel8/8.4/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/appstream/debug',
      'content/e4s/rhel8/8.4/x86_64/appstream/os',
      'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/baseos/debug',
      'content/e4s/rhel8/8.4/x86_64/baseos/os',
      'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.4/x86_64/highavailability/os',
      'content/e4s/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sap/debug',
      'content/e4s/rhel8/8.4/x86_64/sap/os',
      'content/e4s/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/appstream/debug',
      'content/eus/rhel8/8.4/ppc64le/appstream/os',
      'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/baseos/debug',
      'content/eus/rhel8/8.4/ppc64le/baseos/os',
      'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.4/ppc64le/highavailability/os',
      'content/eus/rhel8/8.4/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.4/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.4/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sap/debug',
      'content/eus/rhel8/8.4/ppc64le/sap/os',
      'content/eus/rhel8/8.4/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.4/ppc64le/supplementary/os',
      'content/eus/rhel8/8.4/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/appstream/debug',
      'content/eus/rhel8/8.4/x86_64/appstream/os',
      'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/baseos/debug',
      'content/eus/rhel8/8.4/x86_64/baseos/os',
      'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/highavailability/debug',
      'content/eus/rhel8/8.4/x86_64/highavailability/os',
      'content/eus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.4/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.4/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sap/debug',
      'content/eus/rhel8/8.4/x86_64/sap/os',
      'content/eus/rhel8/8.4/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/supplementary/debug',
      'content/eus/rhel8/8.4/x86_64/supplementary/os',
      'content/eus/rhel8/8.4/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/appstream/debug',
      'content/tus/rhel8/8.4/x86_64/appstream/os',
      'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/baseos/debug',
      'content/tus/rhel8/8.4/x86_64/baseos/os',
      'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/highavailability/debug',
      'content/tus/rhel8/8.4/x86_64/highavailability/os',
      'content/tus/rhel8/8.4/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/nfv/debug',
      'content/tus/rhel8/8.4/x86_64/nfv/os',
      'content/tus/rhel8/8.4/x86_64/nfv/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/rt/debug',
      'content/tus/rhel8/8.4/x86_64/rt/os',
      'content/tus/rhel8/8.4/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'exiv2-0.27.2-5.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-devel-0.27.2-5.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-doc-0.27.2-5.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-libs-0.27.2-5.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gegl-0.2.0-39.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-color-manager-3.28.0-3.el8', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-color-manager-3.28.0-3.el8', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgexiv2-0.10.8-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgexiv2-devel-0.10.8-4.el8', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.6/x86_64/appstream/debug',
      'content/aus/rhel8/8.6/x86_64/appstream/os',
      'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.6/x86_64/baseos/debug',
      'content/aus/rhel8/8.6/x86_64/baseos/os',
      'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.6/ppc64le/appstream/os',
      'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.6/ppc64le/baseos/os',
      'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap/os',
      'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/appstream/debug',
      'content/e4s/rhel8/8.6/x86_64/appstream/os',
      'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/baseos/debug',
      'content/e4s/rhel8/8.6/x86_64/baseos/os',
      'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.6/x86_64/highavailability/os',
      'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap/debug',
      'content/e4s/rhel8/8.6/x86_64/sap/os',
      'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/appstream/debug',
      'content/eus/rhel8/8.6/ppc64le/appstream/os',
      'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/baseos/debug',
      'content/eus/rhel8/8.6/ppc64le/baseos/os',
      'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.6/ppc64le/highavailability/os',
      'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap/debug',
      'content/eus/rhel8/8.6/ppc64le/sap/os',
      'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.6/ppc64le/supplementary/os',
      'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/appstream/debug',
      'content/eus/rhel8/8.6/x86_64/appstream/os',
      'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/baseos/debug',
      'content/eus/rhel8/8.6/x86_64/baseos/os',
      'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/highavailability/debug',
      'content/eus/rhel8/8.6/x86_64/highavailability/os',
      'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap/debug',
      'content/eus/rhel8/8.6/x86_64/sap/os',
      'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/supplementary/debug',
      'content/eus/rhel8/8.6/x86_64/supplementary/os',
      'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/appstream/debug',
      'content/tus/rhel8/8.6/x86_64/appstream/os',
      'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/baseos/debug',
      'content/tus/rhel8/8.6/x86_64/baseos/os',
      'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/highavailability/debug',
      'content/tus/rhel8/8.6/x86_64/highavailability/os',
      'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/rt/os',
      'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'exiv2-0.27.2-5.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-devel-0.27.2-5.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-doc-0.27.2-5.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-libs-0.27.2-5.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gegl-0.2.0-39.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-color-manager-3.28.0-3.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-color-manager-3.28.0-3.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgexiv2-0.10.8-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgexiv2-devel-0.10.8-4.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8/ppc64le/appstream/debug',
      'content/dist/rhel8/8/ppc64le/appstream/os',
      'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/highavailability/debug',
      'content/dist/rhel8/8/ppc64le/highavailability/os',
      'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
      'content/dist/rhel8/8/ppc64le/sap-solutions/os',
      'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap/debug',
      'content/dist/rhel8/8/ppc64le/sap/os',
      'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/supplementary/debug',
      'content/dist/rhel8/8/ppc64le/supplementary/os',
      'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/highavailability/debug',
      'content/dist/rhel8/8/x86_64/highavailability/os',
      'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/x86_64/nfv/debug',
      'content/dist/rhel8/8/x86_64/nfv/os',
      'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8/x86_64/resilientstorage/os',
      'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/x86_64/rt/debug',
      'content/dist/rhel8/8/x86_64/rt/os',
      'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap-solutions/debug',
      'content/dist/rhel8/8/x86_64/sap-solutions/os',
      'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap/debug',
      'content/dist/rhel8/8/x86_64/sap/os',
      'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
      'content/dist/rhel8/8/x86_64/supplementary/debug',
      'content/dist/rhel8/8/x86_64/supplementary/os',
      'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'exiv2-0.27.2-5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-devel-0.27.2-5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-doc-0.27.2-5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'exiv2-libs-0.27.2-5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gegl-0.2.0-39.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-color-manager-3.28.0-3.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gnome-color-manager-3.28.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgexiv2-0.10.8-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgexiv2-devel-0.10.8-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exiv2 / exiv2-devel / exiv2-doc / exiv2-libs / gegl / etc');
}
