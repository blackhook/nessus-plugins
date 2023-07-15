#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5347. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171497);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id("CVE-2022-44267", "CVE-2022-44268");
  script_xref(name:"IAVB", value:"2023-B-0006-S");

  script_name(english:"Debian DSA-5347-1 : imagemagick - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5347 advisory.

  - ImageMagick 7.1.0-49 is vulnerable to Denial of Service. When it parses a PNG image (e.g., for resize),
    the convert process could be left waiting for stdin input. (CVE-2022-44267)

  - ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for
    resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary
    has permissions to read it). (CVE-2022-44268)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/imagemagick");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5347");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44267");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44268");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/imagemagick");
  script_set_attribute(attribute:"solution", value:
"Upgrade the imagemagick packages.

For the stable distribution (bullseye), these problems have been fixed in version 8");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44268");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/15");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'imagemagick', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'imagemagick-6-common', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'imagemagick-6-doc', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'imagemagick-6.q16', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'imagemagick-6.q16hdri', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'imagemagick-common', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'imagemagick-doc', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libimage-magick-perl', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libimage-magick-q16-perl', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libimage-magick-q16hdri-perl', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagick++-6-headers', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagick++-6.q16-8', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagick++-6.q16-dev', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagick++-6.q16hdri-8', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagick++-6.q16hdri-dev', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagick++-dev', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickcore-6-arch-config', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickcore-6-headers', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickcore-6.q16-6', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickcore-6.q16-6-extra', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickcore-6.q16-dev', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickcore-6.q16hdri-6', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickcore-6.q16hdri-6-extra', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickcore-6.q16hdri-dev', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickcore-dev', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickwand-6-headers', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickwand-6.q16-6', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickwand-6.q16-dev', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickwand-6.q16hdri-6', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickwand-6.q16hdri-dev', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'libmagickwand-dev', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'},
    {'release': '11.0', 'prefix': 'perlmagick', 'reference': '8:6.9.11.60+dfsg-1.3+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'imagemagick / imagemagick-6-common / imagemagick-6-doc / etc');
}
