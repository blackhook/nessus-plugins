#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3007. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161205);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2021-3596", "CVE-2022-28463");

  script_name(english:"Debian DLA-3007-1 : imagemagick - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3007 advisory.

  - A NULL pointer dereference flaw was found in ImageMagick in versions prior to 7.0.10-31 in ReadSVGImage()
    in coders/svg.c. This issue is due to not checking the return value from libxml2's
    xmlCreatePushParserCtxt() and uses the value directly, which leads to a crash and segmentation fault.
    (CVE-2021-3596)

  - ImageMagick 7.1.0-27 is vulnerable to Buffer Overflow. (CVE-2022-28463)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/imagemagick");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3007");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3596");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28463");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/imagemagick");
  script_set_attribute(attribute:"solution", value:
"Upgrade the imagemagick packages.

For Debian 9 stretch, these problems have been fixed in version 8");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28463");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16hdri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16hdri-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'imagemagick', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'imagemagick-6-common', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'imagemagick-6-doc', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'imagemagick-6.q16', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'imagemagick-6.q16hdri', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'imagemagick-common', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'imagemagick-doc', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libimage-magick-perl', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libimage-magick-q16-perl', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libimage-magick-q16hdri-perl', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagick++-6-headers', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagick++-6.q16-7', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagick++-6.q16-dev', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagick++-6.q16hdri-7', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagick++-6.q16hdri-dev', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagick++-dev', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickcore-6-arch-config', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickcore-6-headers', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickcore-6.q16-3', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickcore-6.q16-3-extra', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickcore-6.q16-dev', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickcore-6.q16hdri-3', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickcore-6.q16hdri-3-extra', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickcore-6.q16hdri-dev', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickcore-dev', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickwand-6-headers', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickwand-6.q16-3', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickwand-6.q16-dev', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickwand-6.q16hdri-3', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickwand-6.q16hdri-dev', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'libmagickwand-dev', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'},
    {'release': '9.0', 'prefix': 'perlmagick', 'reference': '8:6.9.7.4+dfsg-11+deb9u14'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'imagemagick / imagemagick-6-common / imagemagick-6-doc / etc');
}
