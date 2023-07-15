#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5126. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(160402);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/02");

  script_name(english:"Debian DSA-5126-1 : ffmpeg - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dsa-5126
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ffmpeg");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5126");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ffmpeg");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ffmpeg packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-extra7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavresample4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale5");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'ffmpeg', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'ffmpeg-doc', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavcodec-dev', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavcodec-extra', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavcodec-extra58', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavcodec58', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavdevice-dev', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavdevice58', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavfilter-dev', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavfilter-extra', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavfilter-extra7', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavfilter7', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavformat-dev', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavformat58', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavresample-dev', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavresample4', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavutil-dev', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavutil56', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libpostproc-dev', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libpostproc55', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libswresample-dev', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libswresample3', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libswscale-dev', 'reference': '7:4.1.9-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libswscale5', 'reference': '7:4.1.9-0+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / ffmpeg-doc / libavcodec-dev / libavcodec-extra / etc');
}
