#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5031. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156266);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2021-30887", "CVE-2021-30890");
  script_xref(name:"IAVA", value:"2021-A-0505-S");

  script_name(english:"Debian DSA-5031-1 : wpewebkit - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5031 advisory.

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.0.1, iOS
    15.1 and iPadOS 15.1, watchOS 8.1, tvOS 15.1. Processing maliciously crafted web content may lead to
    unexpectedly unenforced Content Security Policy. (CVE-2021-30887)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.0.1,
    iOS 15.1 and iPadOS 15.1, watchOS 8.1, tvOS 15.1. Processing maliciously crafted web content may lead to
    universal cross site scripting. (CVE-2021-30890)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wpewebkit");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5031");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-30887");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-30890");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/wpewebkit");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wpewebkit packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.34.3-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30890");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30887");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpewebkit-1.0-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpewebkit-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpewebkit-1.0-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpewebkit-driver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libwpewebkit-1.0-3', 'reference': '2.34.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwpewebkit-1.0-dev', 'reference': '2.34.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwpewebkit-1.0-doc', 'reference': '2.34.3-1~deb11u1'},
    {'release': '11.0', 'prefix': 'wpewebkit-driver', 'reference': '2.34.3-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwpewebkit-1.0-3 / libwpewebkit-1.0-dev / libwpewebkit-1.0-doc / etc');
}
