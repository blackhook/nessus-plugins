#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5288. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168194);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/25");

  script_cve_id("CVE-2022-1270");

  script_name(english:"Debian DSA-5288-1 : graphicsmagick - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5288
advisory.

  - In GraphicsMagick, a heap buffer overflow was found when parsing MIFF. (CVE-2022-1270)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/graphicsmagick
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e247f871");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5288");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1270");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/graphicsmagick");
  script_set_attribute(attribute:"solution", value:
"Upgrade the graphicsmagick packages.

For the stable distribution (bullseye), this problem has been fixed in version 1.4+really1.3.36+hg16481-2+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1270");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-imagemagick-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-libmagick-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphics-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick++-q16-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick++1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick-q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick1-dev");
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

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'graphicsmagick', 'reference': '1.4+really1.3.36+hg16481-2+deb11u1'},
    {'release': '11.0', 'prefix': 'graphicsmagick-dbg', 'reference': '1.4+really1.3.36+hg16481-2+deb11u1'},
    {'release': '11.0', 'prefix': 'graphicsmagick-imagemagick-compat', 'reference': '1.4+really1.3.36+hg16481-2+deb11u1'},
    {'release': '11.0', 'prefix': 'graphicsmagick-libmagick-dev-compat', 'reference': '1.4+really1.3.36+hg16481-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libgraphics-magick-perl', 'reference': '1.4+really1.3.36+hg16481-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libgraphicsmagick++-q16-12', 'reference': '1.4+really1.3.36+hg16481-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libgraphicsmagick++1-dev', 'reference': '1.4+really1.3.36+hg16481-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libgraphicsmagick-q16-3', 'reference': '1.4+really1.3.36+hg16481-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libgraphicsmagick1-dev', 'reference': '1.4+really1.3.36+hg16481-2+deb11u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'graphicsmagick / graphicsmagick-dbg / etc');
}
