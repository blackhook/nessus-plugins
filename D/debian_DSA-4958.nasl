#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4958. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152565);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/14");

  script_cve_id(
    "CVE-2019-20421",
    "CVE-2021-3482",
    "CVE-2021-29457",
    "CVE-2021-29473",
    "CVE-2021-31292"
  );

  script_name(english:"Debian DSA-4958-1 : exiv2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4958 advisory.

  - In Jp2Image::readMetadata() in jp2image.cpp in Exiv2 0.27.2, an input file can result in an infinite loop
    and hang, with high CPU consumption. Remote attackers could leverage this vulnerability to cause a denial
    of service via a crafted file. (CVE-2019-20421)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. A heap buffer overflow was found in Exiv2 versions v0.27.3 and earlier. The heap overflow
    is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could potentially
    exploit the vulnerability to gain code execution, if they can trick the victim into running Exiv2 on a
    crafted image file. Note that this bug is only triggered when _writing_ the metadata, which is a less
    frequently used Exiv2 operation than _reading_ the metadata. For example, to trigger the bug in the Exiv2
    command-line application, you need to add an extra command-line argument such as `insert`. The bug is
    fixed in version v0.27.4. (CVE-2021-29457)

  - Exiv2 is a C++ library and a command-line utility to read, write, delete and modify Exif, IPTC, XMP and
    ICC image metadata. An out-of-bounds read was found in Exiv2 versions v0.27.3 and earlier. Exiv2 is a
    command-line utility and C++ library for reading, writing, deleting, and modifying the metadata of image
    files. The out-of-bounds read is triggered when Exiv2 is used to write metadata into a crafted image file.
    An attacker could potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if
    they can trick the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered
    when writing the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For
    example, to trigger the bug in the Exiv2 command-line application, you need to add an extra command-line
    argument such as `insert`. The bug is fixed in version v0.27.4. Please see our security policy for
    information about Exiv2 security. (CVE-2021-29473)

  - An integer overflow in CrwMap::encode0x1810 of Exiv2 0.27.3 allows attackers to trigger a heap-based
    buffer overflow and cause a denial of service (DOS) via crafted metadata. (CVE-2021-31292)

  - A flaw was found in Exiv2 in versions before and including 0.27.4-RC1. Improper input validation of the
    rawData.size property in Jp2Image::readMetadata() in jp2image.cpp can lead to a heap-based buffer overflow
    via a crafted JPG image containing malicious EXIF data. (CVE-2021-3482)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/exiv2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4958");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-20421");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-29457");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-29473");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31292");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3482");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/exiv2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the exiv2 packages.

For the stable distribution (buster), these problems have been fixed in version 0.25-4+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29457");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'exiv2', 'reference': '0.25-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libexiv2-14', 'reference': '0.25-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libexiv2-dev', 'reference': '0.25-4+deb10u2'},
    {'release': '10.0', 'prefix': 'libexiv2-doc', 'reference': '0.25-4+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
