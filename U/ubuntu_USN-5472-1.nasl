##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5472-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161986);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2020-20445",
    "CVE-2020-20446",
    "CVE-2020-20450",
    "CVE-2020-20453",
    "CVE-2020-21041",
    "CVE-2020-21688",
    "CVE-2020-21697",
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
    "CVE-2020-22042",
    "CVE-2020-35965",
    "CVE-2021-38114",
    "CVE-2021-38171",
    "CVE-2021-38291",
    "CVE-2022-1475"
  );
  script_xref(name:"USN", value:"5472-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : FFmpeg vulnerabilities (USN-5472-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5472-1 advisory.

  - FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/lpc.h, which allows a remote malicious
    user to cause a Denial of Service. (CVE-2020-20445)

  - FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/aacpsy.c, which allows a remote malicious
    user to cause a Denial of Service. (CVE-2020-20446)

  - FFmpeg 4.2 is affected by null pointer dereference passed as argument to libavformat/aviobuf.c, which
    could cause a Denial of Service. (CVE-2020-20450)

  - FFmpeg 4.2 is affected by a Divide By Zero issue via libavcodec/aaccoder, which allows a remote malicious
    user to cause a Denial of Service (CVE-2020-20453)

  - Buffer Overflow vulnerability exists in FFmpeg 4.1 via apng_do_inverse_blend in libavcodec/pngenc.c, which
    could let a remote malicious user cause a Denial of Service (CVE-2020-21041)

  - A heap-use-after-free in the av_freep function in libavutil/mem.c of FFmpeg 4.2 allows attackers to
    execute arbitrary code. (CVE-2020-21688)

  - A heap-use-after-free in the mpeg_mux_write_packet function in libavformat/mpegenc.c of FFmpeg 4.2 allows
    to cause a denial of service (DOS) via a crafted avi file. (CVE-2020-21697)

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

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak is affected by: memory leak in
    the link_filter_inouts function in libavfilter/graphparser.c. (CVE-2020-22042)

  - decode_frame in libavcodec/exr.c in FFmpeg 4.3.1 has an out-of-bounds write because of errors in
    calculations of when to perform memset zero operations. (CVE-2020-35965)

  - libavcodec/dnxhddec.c in FFmpeg 4.4 does not check the return value of the init_vlc function, a similar
    issue to CVE-2013-0868. (CVE-2021-38114)

  - adts_decode_extradata in libavformat/adtsenc.c in FFmpeg 4.4 does not check the init_get_bits return
    value, which is a necessary step because the second argument to init_get_bits can be crafted.
    (CVE-2021-38171)

  - FFmpeg version (git commit de8e6e67e7523e48bb27ac224a0b446df05e1640) suffers from a an assertion failure
    at src/libavutil/mathematics.c. (CVE-2021-38291)

  - An integer overflow vulnerability was found in FFmpeg 5.0.1 and in previous versions in g729_parse() in
    llibavcodec/g729_parser.c when processing a specially crafted file. (CVE-2022-1475)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5472-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38171");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-extra58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'ffmpeg', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-extra57', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavcodec57', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavdevice57', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-extra', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-extra6', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavfilter6', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavformat57', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavresample-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavresample3', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libavutil55', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libpostproc54', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libswresample2', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libswscale4', 'pkgver': '7:3.4.11-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'ffmpeg', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavcodec-extra58', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavcodec58', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavdevice58', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavfilter-extra', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavfilter-extra7', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavfilter7', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavformat58', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavresample-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavresample4', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libavutil56', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libpostproc55', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libswresample3', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libswscale5', 'pkgver': '7:4.2.7-0ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'ffmpeg', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavcodec-dev', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavcodec-extra', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavcodec-extra58', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavcodec58', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavdevice-dev', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavdevice58', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavfilter-dev', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavfilter-extra', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavfilter-extra7', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavfilter7', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavformat-dev', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavformat-extra', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavformat-extra58', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavformat58', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavutil-dev', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libavutil56', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libpostproc-dev', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libpostproc55', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libswresample-dev', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libswresample3', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libswscale-dev', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libswscale5', 'pkgver': '7:4.4.2-0ubuntu0.21.10.1'},
    {'osver': '22.04', 'pkgname': 'ffmpeg', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavcodec-extra58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavcodec58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavdevice58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavfilter-extra', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavfilter-extra7', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavfilter7', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavformat-extra', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavformat-extra58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavformat58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libavutil56', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpostproc55', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libswresample3', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libswscale5', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / libavcodec-dev / libavcodec-extra / libavcodec-extra57 / etc');
}
