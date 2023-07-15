#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4998. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154772);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/01");

  script_cve_id(
    "CVE-2020-20445",
    "CVE-2020-20446",
    "CVE-2020-20450",
    "CVE-2020-20453",
    "CVE-2020-21688",
    "CVE-2020-21697",
    "CVE-2020-22037",
    "CVE-2020-22042",
    "CVE-2021-38114",
    "CVE-2021-38171",
    "CVE-2021-38291"
  );

  script_name(english:"Debian DSA-4998-1 : ffmpeg - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4998 advisory.

  - FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/lpc.h, which allows a remote malicious
    user to cause a Denial of Service. (CVE-2020-20445)

  - FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/aacpsy.c, which allows a remote malicious
    user to cause a Denial of Service. (CVE-2020-20446)

  - FFmpeg 4.2 is affected by null pointer dereference passed as argument to libavformat/aviobuf.c, which
    could cause a Denial of Service. (CVE-2020-20450)

  - FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/aaccoder, which allows a remote malicious
    user to cause a Denial of Service (CVE-2020-20453)

  - A heap-use-after-free in the av_freep function in libavutil/mem.c of FFmpeg 4.2 allows attackers to
    execute arbitrary code. (CVE-2020-21688)

  - A heap-use-after-free in the mpeg_mux_write_packet function in libavformat/mpegenc.c of FFmpeg 4.2 allows
    to cause a denial of service (DOS) via a crafted avi file. (CVE-2020-21697)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in avcodec_alloc_context3 at
    options.c. (CVE-2020-22037)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak is affected by: memory leak in
    the link_filter_inouts function in libavfilter/graphparser.c. (CVE-2020-22042)

  - libavcodec/dnxhddec.c in FFmpeg 4.4 does not check the return value of the init_vlc function, a similar
    issue to CVE-2013-0868. (CVE-2021-38114)

  - adts_decode_extradata in libavformat/adtsenc.c in FFmpeg 4.4 does not check the init_get_bits return
    value, which is a necessary step because the second argument to init_get_bits can be crafted.
    (CVE-2021-38171)

  - FFmpeg version (git commit de8e6e67e7523e48bb27ac224a0b446df05e1640) suffers from a an assertion failure
    at src/libavutil/mathematics.c. (CVE-2021-38291)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ffmpeg");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4998");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-20445");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-20446");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-20450");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-20453");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21688");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21697");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22037");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22042");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38114");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38171");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38291");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/ffmpeg");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ffmpeg packages.

For the stable distribution (bullseye), these problems have been fixed in version 7");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38171");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/01");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'ffmpeg', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'ffmpeg-doc', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavcodec-dev', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavcodec-extra', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavcodec-extra58', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavcodec58', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavdevice-dev', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavdevice58', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavfilter-dev', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavfilter-extra', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavfilter-extra7', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavfilter7', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavformat-dev', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavformat58', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavresample-dev', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavresample4', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavutil-dev', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libavutil56', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libpostproc-dev', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libpostproc55', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libswresample-dev', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libswresample3', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libswscale-dev', 'reference': '7:4.3.3-0+deb11u1'},
    {'release': '11.0', 'prefix': 'libswscale5', 'reference': '7:4.3.3-0+deb11u1'}
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
