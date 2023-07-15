#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5241. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165546);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2022-32886");

  script_name(english:"Debian DSA-5241-1 : wpewebkit - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5241
advisory.

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in Safari 16, iOS
    16, iOS 15.7 and iPadOS 15.7. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2022-32886)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wpewebkit");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5241");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32886");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/wpewebkit");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wpewebkit packages.

For the stable distribution (bullseye), this problem has been fixed in version 2.38.0-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32886");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpewebkit-1.0-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpewebkit-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpewebkit-1.0-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpewebkit-driver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libwpewebkit-1.0-3', 'reference': '2.38.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwpewebkit-1.0-dev', 'reference': '2.38.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwpewebkit-1.0-doc', 'reference': '2.38.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'wpewebkit-driver', 'reference': '2.38.0-1~deb11u1'}
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
    severity   : SECURITY_HOLE,
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
