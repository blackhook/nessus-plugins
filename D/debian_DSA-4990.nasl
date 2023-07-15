#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4990. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154263);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/20");

  script_cve_id(
    "CVE-2020-20445",
    "CVE-2020-20446",
    "CVE-2020-20453",
    "CVE-2020-21041",
    "CVE-2020-22015",
    "CVE-2020-22016",
    "CVE-2020-22017",
    "CVE-2020-22019",
    "CVE-2020-22020",
    "CVE-2020-22021",
    "CVE-2020-22022",
    "CVE-2020-22023",
    "CVE-2020-22025",
    "CVE-2020-22026",
    "CVE-2020-22027",
    "CVE-2020-22028",
    "CVE-2020-22029",
    "CVE-2020-22030",
    "CVE-2020-22031",
    "CVE-2020-22032",
    "CVE-2020-22033",
    "CVE-2020-22034",
    "CVE-2020-22035",
    "CVE-2020-22036",
    "CVE-2020-22037",
    "CVE-2020-22049",
    "CVE-2020-22054",
    "CVE-2020-35965",
    "CVE-2021-38114",
    "CVE-2021-38171",
    "CVE-2021-38291"
  );

  script_name(english:"Debian DSA-4990-1 : ffmpeg - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4990 advisory.

  - FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/lpc.h, which allows a remote malicious
    user to cause a Denial of Service. (CVE-2020-20445)

  - FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/aacpsy.c, which allows a remote malicious
    user to cause a Denial of Service. (CVE-2020-20446)

  - FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/aaccoder, which allows a remote malicious
    user to cause a Denial of Service (CVE-2020-20453)

  - Buffer Overflow vulnerability exists in FFmpeg 4.1 via apng_do_inverse_blend in libavcodec/pngenc.c, which
    could let a remote malicious user cause a Denial of Service (CVE-2020-21041)

  - Buffer Overflow vulnerability in FFmpeg 4.2 in mov_write_video_tag due to the out of bounds in
    libavformat/movenc.c, which could let a remote malicious user obtain sensitive information, cause a Denial
    of Service, or execute arbitrary code. (CVE-2020-22015)

  - A heap-based Buffer Overflow vulnerability in FFmpeg 4.2 at libavcodec/get_bits.h when writing .mov files,
    which might lead to memory corruption and other potential consequences. (CVE-2020-22016)

  - A heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 at ff_fill_rectangle in
    libavfilter/drawutils.c, which might lead to memory corruption and other potential consequences.
    (CVE-2020-22017)

  - Buffer Overflow vulnerability in FFmpeg 4.2 at convolution_y_10bit in libavfilter/vf_vmafmotion.c, which
    could let a remote malicious user cause a Denial of Service. (CVE-2020-22019)

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

  - A heap-based Buffer Overflow vulnerability exits in FFmpeg 4.2 in deflate16 at libavfilter/vf_neighbor.c,
    which might lead to memory corruption and other potential consequences. (CVE-2020-22027)

  - Buffer Overflow vulnerability exists in FFmpeg 4.2 in filter_vertically_8 at libavfilter/vf_avgblur.c,
    which could cause a remote Denial of Service. (CVE-2020-22028)

  - A heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 at libavfilter/vf_colorconstancy.c: in
    slice_get_derivative, which crossfade_samples_fltp, which might lead to memory corruption and other
    potential consequences. (CVE-2020-22029)

  - A heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 at libavfilter/af_afade.c in
    crossfade_samples_fltp, which might lead to memory corruption and other potential consequences.
    (CVE-2020-22030)

  - A Heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 at libavfilter/vf_w3fdif.c in
    filter16_complex_low, which might lead to memory corruption and other potential consequences.
    (CVE-2020-22031)

  - A heap-based Buffer Overflow vulnerability exists FFmpeg 4.2 at libavfilter/vf_edgedetect.c in
    gaussian_blur, which might lead to memory corruption and other potential consequences. (CVE-2020-22032)

  - A heap-based Buffer Overflow Vulnerability exists FFmpeg 4.2 at libavfilter/vf_vmafmotion.c in
    convolution_y_8bit, which could let a remote malicious user cause a Denial of Service. (CVE-2020-22033)

  - A heap-based Buffer Overflow vulnerability exists FFmpeg 4.2 at libavfilter/vf_floodfill.c, which might
    lead to memory corruption and other potential consequences. (CVE-2020-22034)

  - A heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 in get_block_row at libavfilter/vf_bm3d.c,
    which might lead to memory corruption and other potential consequences. (CVE-2020-22035)

  - A heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 in filter_intra at libavfilter/vf_bwdif.c,
    which might lead to memory corruption and other potential consequences. (CVE-2020-22036)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in avcodec_alloc_context3 at
    options.c. (CVE-2020-22037)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in the wtvfile_open_sector
    function in wtvdec.c. (CVE-2020-22049)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in the av_dict_set function in
    dict.c. (CVE-2020-22054)

  - decode_frame in libavcodec/exr.c in FFmpeg 4.3.1 has an out-of-bounds write because of errors in
    calculations of when to perform memset zero operations. (CVE-2020-35965)

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
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4990");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-20445");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-20446");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-20453");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21041");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22015");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22017");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22019");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22020");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22021");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22022");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22023");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22025");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22026");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22027");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22028");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22029");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22030");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22031");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22032");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22033");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22034");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22035");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22036");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22037");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22049");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22054");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35965");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38114");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38171");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38291");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ffmpeg");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ffmpeg packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38171");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/20");

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
    {'release': '10.0', 'prefix': 'ffmpeg', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'ffmpeg-doc', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavcodec-dev', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavcodec-extra', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavcodec-extra58', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavcodec58', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavdevice-dev', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavdevice58', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavfilter-dev', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavfilter-extra', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavfilter-extra7', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavfilter7', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavformat-dev', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavformat58', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavresample-dev', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavresample4', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavutil-dev', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libavutil56', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libpostproc-dev', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libpostproc55', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libswresample-dev', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libswresample3', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libswscale-dev', 'reference': '7:4.1.8-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libswscale5', 'reference': '7:4.1.8-0+deb10u1'}
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
