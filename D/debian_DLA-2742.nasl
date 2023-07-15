#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2742. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152737);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id(
    "CVE-2020-21041",
    "CVE-2020-22015",
    "CVE-2020-22016",
    "CVE-2020-22020",
    "CVE-2020-22021",
    "CVE-2020-22022",
    "CVE-2020-22023",
    "CVE-2020-22025",
    "CVE-2020-22026",
    "CVE-2020-22028",
    "CVE-2020-22031",
    "CVE-2020-22032",
    "CVE-2020-22036",
    "CVE-2021-3566",
    "CVE-2021-38114"
  );

  script_name(english:"Debian DLA-2742-1 : ffmpeg - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2742 advisory.

  - Buffer Overflow vulnerability exists in FFmpeg 4.1 via apng_do_inverse_blend in libavcodec/pngenc.c, which
    could let a remote malicious user cause a Denial of Service (CVE-2020-21041)

  - Buffer Overflow vulnerability in FFmpeg 4.2 in mov_write_video_tag due to the out of bounds in
    libavformat/movenc.c, which could let a remote malicious user obtain sensitive information, cause a Denial
    of Service, or execute arbitrary code. (CVE-2020-22015)

  - A heap-based Buffer Overflow vulnerability in FFmpeg 4.2 at libavcodec/get_bits.h when writing .mov files,
    which might lead to memory corruption and other potential consequences. (CVE-2020-22016)

  - Buffer Overflow vulnerability in FFmpeg 4.2 in the build_diff_map function in libavfilter/vf_fieldmatch.c,
    which could let a remote malicious user cause a Denial of Service. (CVE-2020-22020)

  - Buffer Overflow vulnerability in FFmpeg 4.2 at filter_edges function in libavfilter/vf_yadif.c, which
    could let a remote malicious user cause a Denial of Service. (CVE-2020-22021)

  - A heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 in filter_frame at
    libavfilter/vf_fieldorder.c, which might lead to memory corruption and other potential consequences.
    (CVE-2020-22022)

  - A heap-based Buffer Overflow vulnerabililty exists in FFmpeg 4.2 in filter_frame at
    libavfilter/vf_bitplanenoise.c, which might lead to memory corruption and other potential consequences.
    (CVE-2020-22023)

  - A heap-based Buffer Overflow vulnerability exists in gaussian_blur at libavfilter/vf_edgedetect.c, which
    might lead to memory corruption and other potential consequences. (CVE-2020-22025)

  - Buffer Overflow vulnerability exists in FFmpeg 4.2 in the config_input function at
    libavfilter/af_tremolo.c, which could let a remote malicious user cause a Denial of Service.
    (CVE-2020-22026)

  - Buffer Overflow vulnerability exists in FFmpeg 4.2 in filter_vertically_8 at libavfilter/vf_avgblur.c,
    which could cause a remote Denial of Service. (CVE-2020-22028)

  - A Heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 at libavfilter/vf_w3fdif.c in
    filter16_complex_low, which might lead to memory corruption and other potential consequences.
    (CVE-2020-22031)

  - A heap-based Buffer Overflow vulnerability exists FFmpeg 4.2 at libavfilter/vf_edgedetect.c in
    gaussian_blur, which might lead to memory corruption and other potential consequences. (CVE-2020-22032)

  - A heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 in filter_intra at libavfilter/vf_bwdif.c,
    which might lead to memory corruption and other potential consequences. (CVE-2020-22036)

  - Prior to ffmpeg version 4.3, the tty demuxer did not have a 'read_probe' function assigned to it. By
    crafting a legitimate ffconcat file that references an image, followed by a file the triggers the tty
    demuxer, the contents of the second file will be copied into the output file verbatim (as long as the
    `-vcodec copy` option is passed to ffmpeg). (CVE-2021-3566)

  - libavcodec/dnxhddec.c in FFmpeg 4.4 does not check the return value of the init_vlc function, a similar
    issue to CVE-2013-0868. (CVE-2021-38114)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ffmpeg");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2742");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21041");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22015");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22020");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22021");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22022");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22023");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22025");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22026");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22028");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22031");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22032");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22036");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3566");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38114");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/ffmpeg");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ffmpeg packages.

For Debian 9 stretch, these problems have been fixed in version 7");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-22036");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-extra6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'ffmpeg', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'ffmpeg-doc', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libav-tools', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavcodec-dev', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavcodec-extra', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavcodec-extra57', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavcodec57', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavdevice-dev', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavdevice57', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavfilter-dev', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavfilter-extra', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavfilter-extra6', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavfilter6', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavformat-dev', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavformat57', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavresample-dev', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavresample3', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavutil-dev', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libavutil55', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libpostproc-dev', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libpostproc54', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libswresample-dev', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libswresample2', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libswscale-dev', 'reference': '7:3.2.15-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libswscale4', 'reference': '7:3.2.15-0+deb9u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / ffmpeg-doc / libav-tools / libavcodec-dev / libavcodec-extra / etc');
}
