#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-172.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106890);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15186", "CVE-2017-15672", "CVE-2017-16840", "CVE-2017-17081", "CVE-2017-17555", "CVE-2018-6392", "CVE-2018-6621");

  script_name(english:"openSUSE Security Update : ffmpeg (openSUSE-2018-172)");
  script_summary(english:"Check for the openSUSE-2018-172 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ffmpeg fixes the following issues :

Updated ffmpeg to new bugfix release 3.4.2

  - Fix integer overflows, multiplication overflows,
    undefined shifts, and verify buffer lengths.

  - avfilter/vf_transpose: Fix used plane count
    [boo#1078488, CVE-2018-6392]

  - avcodec/utvideodec: Fix bytes left check in
    decode_frame() [boo#1079368, CVE-2018-6621] 

  - Enable use of libzvbi for displaying teletext subtitles.

  - Fixed a DoS in swri_audio_convert() [boo#1072366,
    CVE-2017-17555].

Update to new bugfix release 3.4.1

  - Fixed integer overflows, division by zero, illegal bit
    shifts

  - Fixed the gmc_mmx function which failed to validate
    width and height [boo#1070762, CVE-2017-17081]

  - Fixed out-of-bounds in VC-2 encoder [boo#1069407,
    CVE-2017-16840]

  - ffplay: use SDL2 audio API

  - install also doc/ffserver.conf

  - Update to new upstream release 3.4

  - New video filters: deflicker, doublewave, lumakey,
    pixscope, oscilloscope, robterts, limiter, libvmaf,
    unpremultiply, tlut2, floodifll, pseudocolor, despill,
    convolve, vmafmotion.

  - New audio filters: afir, crossfeed, surround, headphone,
    superequalizer, haas.

  - Some video filters with several inputs now use a common
    set of options: blend, libvmaf, lut3d, overlay, psnr,
    ssim. They must always be used by name.

  - librsvg support for svg rasterization

  - spec-compliant VP9 muxing support in MP4

  - Remove the libnut and libschroedinger muxer/demuxer
    wrappers

  - drop deprecated qtkit input device (use avfoundation
    instead)

  - SUP/PGS subtitle muxer

  - VP9 tile threading support

  - KMS screen grabber

  - CUDA thumbnail filter

  - V4L2 mem2mem HW assisted codecs

  - Rockchip MPP hardware decoding

  - (Not in openSUSE builds, only original ones:)

  - Gremlin Digital Video demuxer and decoder

  - Additional frame format support for Interplay MVE movies

  - Dolby E decoder and SMPTE 337M demuxer

  - raw G.726 muxer and demuxer, left- and right-justified

  - NewTek NDI input/output device

  - FITS demuxer, muxer, decoder and encoder

  - Fixed a double free in huffyuv [boo#1064577,
    CVE-2017-15186]

  - Fixed an out-of-bounds in ffv1dec [boo#1066428,
    CVE-2017-15672]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079368"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ffmpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-debuginfo-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ffmpeg-debugsource-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavcodec-devel-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavcodec57-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavcodec57-debuginfo-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavdevice-devel-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavdevice57-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavdevice57-debuginfo-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavfilter-devel-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavfilter6-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavfilter6-debuginfo-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavformat-devel-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavformat57-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavformat57-debuginfo-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavresample-devel-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavresample3-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavresample3-debuginfo-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavutil-devel-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavutil55-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libavutil55-debuginfo-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpostproc-devel-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpostproc54-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpostproc54-debuginfo-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libswresample-devel-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libswresample2-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libswresample2-debuginfo-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libswscale-devel-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libswscale4-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libswscale4-debuginfo-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavcodec57-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavcodec57-debuginfo-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavdevice57-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavdevice57-debuginfo-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavfilter6-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavfilter6-debuginfo-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavformat57-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavformat57-debuginfo-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavresample3-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavresample3-debuginfo-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavutil55-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libavutil55-debuginfo-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpostproc54-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpostproc54-debuginfo-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libswresample2-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libswresample2-debuginfo-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libswscale4-32bit-3.4.2-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libswscale4-debuginfo-32bit-3.4.2-10.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg / ffmpeg-debuginfo / ffmpeg-debugsource / libavcodec-devel / etc");
}
