#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-24.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(132910);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/17");

  script_cve_id("CVE-2017-17555", "CVE-2018-13305", "CVE-2019-11338", "CVE-2019-11339", "CVE-2019-15942");

  script_name(english:"openSUSE Security Update : ffmpeg-4 (openSUSE-2020-24)");
  script_summary(english:"Check for the openSUSE-2020-24 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ffmpeg-4 fixes the following issues :

ffmpeg-4 was updated to version 4.0.5, fixes boo#1133153 

  - CVE-2019-11339: The studio profile decoder in
    libavcodec/mpeg4videodec.c in FFmpeg 4.0 allowed remote
    attackers to cause a denial of service (out-of-array
    access) or possibly have unspecified. (bsc#1133153)

  - For other changes see
    /usr/share/doc/packages/libavcodec58/Changelog

Update to version 4.2.1 :

  - Stable bug fix release, mainly codecs and format fixes.

  - CVE-2019-15942: Conditional jump or move depends on
    uninitialised value' issue in h2645_parse (boo#1149839)

Update to FFmpeg 4.2 'Ada'

  - tpad filter

  - AV1 decoding support through libdav1d

  - dedot filter

  - chromashift and rgbashift filters

  - freezedetect filter

  - truehd_core bitstream filter

  - dhav demuxer

  - PCM-DVD encoder

  - GIF parser

  - vividas demuxer

  - hymt decoder

  - anlmdn filter

  - maskfun filter

  - hcom demuxer and decoder

  - ARBC decoder

  - libaribb24 based ARIB STD-B24 caption support (profiles
    A and C)

  - Support decoding of HEVC 4:4:4 content in nvdec and
    cuviddec

  - removed libndi-newtek

  - agm decoder

  - KUX demuxer

  - AV1 frame split bitstream filter

  - lscr decoder

  - lagfun filter

  - asoftclip filter

  - Support decoding of HEVC 4:4:4 content in vdpau

  - colorhold filter

  - xmedian filter

  - asr filter

  - showspatial multimedia filter

  - VP4 video decoder

  - IFV demuxer

  - derain filter

  - deesser filter

  - mov muxer writes tracks with unspecified language
    instead of English by default

  - added support for using clang to compile CUDA kernels

  - See /usr/share/doc/packages/ffmpeg-4/Changelog for the
    complete changelog.

Update to version 4.1.4

  - See /usr/share/doc/packages/ffmpeg-4/Changelog for the
    complete changelog.

  - Enable runtime enabling for fdkaac via
    --enable-libfdk-aac-dlopen

Update to version 4.1.3 :

  - Updates and bug fixes for codecs, filters and formats.
    [boo#1133153, boo#1133155, CVE-2019-11338,
    CVE-2019-11339]

Update to version 4.1.2 :

  - Updates and bug fixes for codecs, filters and formats.

Update to version 4.1.1 :

  - Various filter and codec fixes and enhancements.

  - configure: Add missing xlib dependency for VAAPI X11
    code.

  - For complete changelog, see
    /usr/share/doc/packages/ffmpeg-4/Changelog

  - enable AV1 support on x86_64

Update ffmpeg to 4.1 :

  - Lots of filter updates as usual: deblock, tmix, aplify,
    fftdnoiz, aderivative, aintegral, pal75bars, pal100bars,
    adeclick, adeclip, lensfun (wrapper), colorconstancy, 1D
    LUT filter (lut1d), cue, acue, transpose_npp, amultiply,
    Block-Matching 3d (bm3d) denoising filter, acrossover
    filter, audio denoiser as afftdn filter, sinc audio
    filter source, chromahold, setparams, vibrance, xstack,
    (a)graphmonitor filter yadif_cuda filter.

  - AV1 parser

  - Support for AV1 in MP4

  - PCM VIDC decoder and encoder

  - libtensorflow backend for DNN based filters like srcnn

  - -- The following only enabled in third-party builds :

  - ATRAC9 decoder

  - AVS2 video decoder via libdavs2

  - IMM4 video decoder

  - Brooktree ProSumer video decoder

  - MatchWare Screen Capture Codec decoder

  - WinCam Motion Video decoder

  - RemotelyAnywhere Screen Capture decoder

  - AVS2 video encoder via libxavs2

  - ILBC decoder

  - SER demuxer

  - Decoding S12M timecode in H264

  - For complete changelog, see
    https://git.ffmpeg.org/gitweb/ffmpeg.git/shortlog/n4.1

Update ffmpeg to 4.0.3 :

  - For complete changelog, see
    https://git.ffmpeg.org/gitweb/ffmpeg.git/shortlog/n4.0.3

  - CVE-2018-13305: Added a missing check for negative
    values of mqaunt variable (boo#1100345)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://git.ffmpeg.org/gitweb/ffmpeg.git/shortlog/n4.0.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://git.ffmpeg.org/gitweb/ffmpeg.git/shortlog/n4.1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ffmpeg-4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-4-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec58-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec58-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec58-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice58-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice58-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice58-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter7-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat58-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat58-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat58-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil56-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc55-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc55-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-debugsource-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-libavcodec-devel-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-libavdevice-devel-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-libavfilter-devel-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-libavformat-devel-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-libavresample-devel-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-libavutil-devel-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-libpostproc-devel-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-libswresample-devel-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-libswscale-devel-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ffmpeg-4-private-devel-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavcodec58-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavcodec58-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavdevice58-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavdevice58-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavfilter7-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavfilter7-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavformat58-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavformat58-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavresample4-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavresample4-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavutil56-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libavutil56-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpostproc55-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpostproc55-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libswresample3-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libswresample3-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libswscale5-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libswscale5-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavcodec58-32bit-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavcodec58-32bit-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavdevice58-32bit-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavdevice58-32bit-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavfilter7-32bit-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavfilter7-32bit-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavformat58-32bit-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavformat58-32bit-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavresample4-32bit-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavresample4-32bit-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavutil56-32bit-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libavutil56-32bit-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpostproc55-32bit-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpostproc55-32bit-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libswresample3-32bit-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libswresample3-32bit-debuginfo-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libswscale5-32bit-4.2.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libswscale5-32bit-debuginfo-4.2.1-lp151.2.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg-4-debugsource / ffmpeg-4-libavcodec-devel / etc");
}
