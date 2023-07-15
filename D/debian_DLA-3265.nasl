#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3265. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169913);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id(
    "CVE-2017-11591",
    "CVE-2017-14859",
    "CVE-2017-14862",
    "CVE-2017-14864",
    "CVE-2017-17669",
    "CVE-2017-18005",
    "CVE-2018-8976",
    "CVE-2018-17581",
    "CVE-2018-19107",
    "CVE-2018-19108",
    "CVE-2018-19535",
    "CVE-2018-20097",
    "CVE-2019-13110",
    "CVE-2019-13112",
    "CVE-2019-13114",
    "CVE-2019-13504",
    "CVE-2019-14369",
    "CVE-2019-14370",
    "CVE-2019-17402",
    "CVE-2020-18771",
    "CVE-2021-29458",
    "CVE-2021-32815",
    "CVE-2021-34334",
    "CVE-2021-37620",
    "CVE-2021-37621",
    "CVE-2021-37622"
  );

  script_name(english:"Debian DLA-3265-1 : exiv2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3265 advisory.

  - There is a Floating point exception in the Exiv2::ValueType function in Exiv2 0.26 that will lead to a
    remote denial of service attack via crafted input. (CVE-2017-11591)

  - An Invalid memory address dereference was discovered in Exiv2::StringValueBase::read in value.cpp in Exiv2
    0.26. The vulnerability causes a segmentation fault and application crash, which leads to denial of
    service. (CVE-2017-14859)

  - An Invalid memory address dereference was discovered in Exiv2::DataValue::read in value.cpp in Exiv2 0.26.
    The vulnerability causes a segmentation fault and application crash, which leads to denial of service.
    (CVE-2017-14862)

  - An Invalid memory address dereference was discovered in Exiv2::getULong in types.cpp in Exiv2 0.26. The
    vulnerability causes a segmentation fault and application crash, which leads to denial of service.
    (CVE-2017-14864)

  - There is a heap-based buffer over-read in the Exiv2::Internal::PngChunk::keyTXTChunk function of
    pngchunk_int.cpp in Exiv2 0.26. A crafted PNG file will lead to a remote denial of service attack.
    (CVE-2017-17669)

  - Exiv2 0.26 has a Null Pointer Dereference in the Exiv2::DataValue::toLong function in value.cpp, related
    to crafted metadata in a TIFF file. (CVE-2017-18005)

  - CiffDirectory::readDirectory() at crwimage_int.cpp in Exiv2 0.26 has excessive stack consumption due to a
    recursive function, leading to Denial of service. (CVE-2018-17581)

  - In Exiv2 0.26, Exiv2::IptcParser::decode in iptc.cpp (called from psdimage.cpp in the PSD image reader)
    may suffer from a denial of service (heap-based buffer over-read) caused by an integer overflow via a
    crafted PSD image file. (CVE-2018-19107)

  - In Exiv2 0.26, Exiv2::PsdImage::readMetadata in psdimage.cpp in the PSD image reader may suffer from a
    denial of service (infinite loop) caused by an integer overflow via a crafted PSD image file.
    (CVE-2018-19108)

  - In Exiv2 0.26 and previous versions, PngChunk::readRawProfile in pngchunk_int.cpp may cause a denial of
    service (application crash due to a heap-based buffer over-read) via a crafted PNG file. (CVE-2018-19535)

  - There is a SEGV in Exiv2::Internal::TiffParserWorker::findPrimaryGroups of tiffimage_int.cpp in Exiv2
    0.27-RC3. A crafted input will lead to a remote denial of service attack. (CVE-2018-20097)

  - In Exiv2 0.26, jpgimage.cpp allows remote attackers to cause a denial of service (image.cpp
    Exiv2::Internal::stringFormat out-of-bounds read) via a crafted file. (CVE-2018-8976)

  - A CiffDirectory::readDirectory integer overflow and out-of-bounds read in Exiv2 through 0.27.1 allows an
    attacker to cause a denial of service (SIGSEGV) via a crafted CRW image file. (CVE-2019-13110)

  - A PngChunk::parseChunkContent uncontrolled memory allocation in Exiv2 through 0.27.1 allows an attacker to
    cause a denial of service (crash due to an std::bad_alloc exception) via a crafted PNG image file.
    (CVE-2019-13112)

  - http.c in Exiv2 through 0.27.1 allows a malicious http server to cause a denial of service (crash due to a
    NULL pointer dereference) by returning a crafted response that lacks a space character. (CVE-2019-13114)

  - There is an out-of-bounds read in Exiv2::MrwImage::readMetadata in mrwimage.cpp in Exiv2 through 0.27.2.
    (CVE-2019-13504)

  - Exiv2::PngImage::readMetadata() in pngimage.cpp in Exiv2 0.27.99.0 allows attackers to cause a denial of
    service (heap-based buffer over-read) via a crafted image file. (CVE-2019-14369)

  - In Exiv2 0.27.99.0, there is an out-of-bounds read in Exiv2::MrwImage::readMetadata() in mrwimage.cpp. It
    could result in denial of service. (CVE-2019-14370)

  - Exiv2 0.27.2 allows attackers to trigger a crash in Exiv2::getULong in types.cpp when called from
    Exiv2::Internal::CiffDirectory::readDirectory in crwimage_int.cpp, because there is no validation of the
    relationship of the total size to the offset and size. (CVE-2019-17402)

  - Exiv2 0.27.99.0 has a global buffer over-read in Exiv2::Internal::Nikon1MakerNote::print0x0088 in
    nikonmn_int.cpp which can result in an information leak. (CVE-2020-18771)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.3 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if they can trick
    the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when writing
    the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application, you need to add an extra command-line argument such
    as insert. The bug is fixed in version v0.27.4. (CVE-2021-29458)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. The assertion failure is triggered when Exiv2 is used to modify the metadata of a crafted
    image file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they
    can trick the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when
    modifying the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For
    example, to trigger the bug in the Exiv2 command-line application, you need to add an extra command-line
    argument such as `fi`. ### Patches The bug is fixed in version v0.27.5. ### References Regression test and
    bug fix: #1739 ### For more information Please see our [security
    policy](https://github.com/Exiv2/exiv2/security/policy) for information about Exiv2 security.
    (CVE-2021-32815)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop is triggered when Exiv2 is used to read the metadata of a crafted image
    file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they can
    trick the victim into running Exiv2 on a crafted image file. The bug is fixed in version v0.27.5.
    (CVE-2021-34334)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.4 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to read the metadata of a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service, if they can trick the victim into
    running Exiv2 on a crafted image file. The bug is fixed in version v0.27.5. (CVE-2021-37620)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop was found in Exiv2 versions v0.27.4 and earlier. The infinite loop is
    triggered when Exiv2 is used to print the metadata of a crafted image file. An attacker could potentially
    exploit the vulnerability to cause a denial of service, if they can trick the victim into running Exiv2 on
    a crafted image file. Note that this bug is only triggered when printing the image ICC profile, which is a
    less frequently used Exiv2 operation that requires an extra command line option (`-p C`). The bug is fixed
    in version v0.27.5. (CVE-2021-37621)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop was found in Exiv2 versions v0.27.4 and earlier. The infinite loop is
    triggered when Exiv2 is used to modify the metadata of a crafted image file. An attacker could potentially
    exploit the vulnerability to cause a denial of service, if they can trick the victim into running Exiv2 on
    a crafted image file. Note that this bug is only triggered when deleting the IPTC data, which is a less
    frequently used Exiv2 operation that requires an extra command line option (`-d I rm`). The bug is fixed
    in version v0.27.5. (CVE-2021-37622)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=876893");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/exiv2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3265");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-11591");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-14859");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-14862");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-14864");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-17669");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-18005");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-17581");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-19107");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-19108");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-19535");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20097");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-8976");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13110");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13112");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13114");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13504");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14369");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14370");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-17402");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-18771");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-29458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32815");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-34334");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37620");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37622");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/exiv2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the exiv2 packages.

For Debian 10 buster, these problems have been fixed in version 0.25-4+deb10u4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-18771");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'exiv2', 'reference': '0.25-4+deb10u4'},
    {'release': '10.0', 'prefix': 'libexiv2-14', 'reference': '0.25-4+deb10u4'},
    {'release': '10.0', 'prefix': 'libexiv2-dev', 'reference': '0.25-4+deb10u4'},
    {'release': '10.0', 'prefix': 'libexiv2-doc', 'reference': '0.25-4+deb10u4'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exiv2 / libexiv2-14 / libexiv2-dev / libexiv2-doc');
}
