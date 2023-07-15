#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5958-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172614);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id(
    "CVE-2022-3109",
    "CVE-2022-3341",
    "CVE-2022-3964",
    "CVE-2022-3965"
  );
  script_xref(name:"USN", value:"5958-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM / 22.10 : FFmpeg vulnerabilities (USN-5958-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5958-1 advisory.

  - An issue was discovered in the FFmpeg package, where vp3_decode_frame in libavcodec/vp3.c lacks check of
    the return value of av_malloc() and will cause a null pointer dereference, impacting availability.
    (CVE-2022-3109)

  - A null pointer dereference issue was discovered in 'FFmpeg' in decode_main_header() function of
    libavformat/nutdec.c file. The flaw occurs because the function lacks check of the return value of
    avformat_new_stream() and triggers the null pointer dereference error, causing an application to crash.
    (CVE-2022-3341)

  - A vulnerability classified as problematic has been found in ffmpeg. This affects an unknown part of the
    file libavcodec/rpzaenc.c of the component QuickTime RPZA Video Encoder. The manipulation of the argument
    y_size leads to out-of-bounds read. It is possible to initiate the attack remotely. The name of the patch
    is 92f9b28ed84a77138105475beba16c146bdaf984. It is recommended to apply a patch to fix this issue. The
    associated identifier of this vulnerability is VDB-213543. (CVE-2022-3964)

  - A vulnerability classified as problematic was found in ffmpeg. This vulnerability affects the function
    smc_encode_stream of the file libavcodec/smcenc.c of the component QuickTime Graphics Video Encoder. The
    manipulation of the argument y_size leads to out-of-bounds read. The attack can be initiated remotely. The
    name of the patch is 13c13109759090b7f7182480d075e13b36ed8edd. It is recommended to apply a patch to fix
    this issue. The identifier of this vulnerability is VDB-213544. (CVE-2022-3965)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5958-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3965");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libav-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra59");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-ffmpeg-extra56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-ffmpeg56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec59");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice-ffmpeg56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice59");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-ffmpeg5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-extra58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-extra59");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-ffmpeg56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat59");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample-ffmpeg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil-ffmpeg54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc-ffmpeg53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample-ffmpeg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale-ffmpeg3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'ffmpeg', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libav-tools', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavcodec-ffmpeg-extra56', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavcodec-ffmpeg56', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavdevice-ffmpeg56', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavfilter-ffmpeg5', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavformat-ffmpeg56', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavresample-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavresample-ffmpeg2', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libavutil-ffmpeg54', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libpostproc-ffmpeg53', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libswresample-ffmpeg1', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '16.04', 'pkgname': 'libswscale-ffmpeg3', 'pkgver': '7:2.8.17-0ubuntu0.1+esm5'},
    {'osver': '18.04', 'pkgname': 'ffmpeg', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavcodec-extra57', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavcodec57', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavdevice57', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-extra', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavfilter-extra6', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavfilter6', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavformat57', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavresample-dev', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavresample3', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libavutil55', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libpostproc54', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libswresample2', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libswscale4', 'pkgver': '7:3.4.11-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'ffmpeg', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavcodec-extra58', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavcodec58', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavdevice58', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavfilter-extra', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavfilter-extra7', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavfilter7', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavformat58', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavresample-dev', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavresample4', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libavutil56', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libpostproc55', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libswresample3', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '20.04', 'pkgname': 'libswscale5', 'pkgver': '7:4.2.7-0ubuntu0.1+esm1'},
    {'osver': '22.04', 'pkgname': 'ffmpeg', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavcodec-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavcodec-extra', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavcodec-extra58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavcodec58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavdevice-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavdevice58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavfilter-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavfilter-extra', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavfilter-extra7', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavfilter7', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavformat-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavformat-extra', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavformat-extra58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavformat58', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavutil-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libavutil56', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libpostproc-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libpostproc55', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libswresample-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libswresample3', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libswscale-dev', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.04', 'pkgname': 'libswscale5', 'pkgver': '7:4.4.2-0ubuntu0.22.04.1+esm1'},
    {'osver': '22.10', 'pkgname': 'ffmpeg', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavcodec-dev', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavcodec-extra', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavcodec-extra59', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavcodec59', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavdevice-dev', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavdevice59', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavfilter-dev', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavfilter-extra', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavfilter-extra8', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavfilter8', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavformat-dev', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavformat-extra', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavformat-extra59', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavformat59', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavutil-dev', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libavutil57', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libpostproc-dev', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libpostproc56', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libswresample-dev', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libswresample4', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libswscale-dev', 'pkgver': '7:5.1.1-1ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libswscale6', 'pkgver': '7:5.1.1-1ubuntu2.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / libav-tools / libavcodec-dev / libavcodec-extra / etc');
}
