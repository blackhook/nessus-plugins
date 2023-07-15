#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3186. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(167277);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/11");

  script_cve_id("CVE-2017-11683", "CVE-2020-19716", "CVE-2022-3756");

  script_name(english:"Debian DLA-3186-1 : exiv2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3186 advisory.

  - There is a reachable assertion in the Internal::TiffReader::visitDirectory function in tiffvisitor.cpp of
    Exiv2 0.26 that will lead to a remote denial of service attack via crafted input. (CVE-2017-11683)

  - A buffer overflow vulnerability in the Databuf function in types.cpp of Exiv2 v0.27.1 leads to a denial of
    service (DOS). (CVE-2020-19716)

  - A vulnerability was found in Exiv2. It has been classified as critical. Affected is the function
    QuickTimeVideo::userDataDecoder of the file quicktimevideo.cpp of the component QuickTime Video Handler.
    The manipulation leads to integer overflow. It is possible to launch the attack remotely. The name of the
    patch is bf4f28b727bdedbd7c88179c30d360e54568a62e. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-212496. (CVE-2022-3756)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=876893");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/exiv2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3186");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-11683");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-19716");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3756");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/exiv2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the exiv2 packages.

For Debian 10 buster, these problems have been fixed in version 0.25-4+deb10u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-19716");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3756");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'exiv2', 'reference': '0.25-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libexiv2-14', 'reference': '0.25-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libexiv2-dev', 'reference': '0.25-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libexiv2-doc', 'reference': '0.25-4+deb10u3'}
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
