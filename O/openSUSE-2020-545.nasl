#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-545.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136008);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/29");

  script_cve_id("CVE-2019-13602", "CVE-2019-13962", "CVE-2019-14437", "CVE-2019-14438", "CVE-2019-14498", "CVE-2019-14533", "CVE-2019-14534", "CVE-2019-14535", "CVE-2019-14776", "CVE-2019-14777", "CVE-2019-14778", "CVE-2019-14970");

  script_name(english:"openSUSE Security Update : vlc (openSUSE-2020-545)");
  script_summary(english:"Check for the openSUSE-2020-545 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for vlc fixes the following issues :

vlc was updated to version 3.0.9.2 :

  + Misc: Properly bump the version in configure.ac.

Changes from version 3.0.9.1 :

  + Misc: Fix VLSub returning 401 for earch request.

Changes from version 3.0.9 :

  + Core: Work around busy looping when playing an invalid
    item through VLM.

  + Access :

  - Multiple dvdread and dvdnav crashs fixes

  - Fixed DVD glitches on clip change

  - Fixed dvdread commands/data sequence inversion in some
    cases causing unwanted glitches

  - Better handling of authored as corrupted DVD

  - Added libsmb2 support for SMB2/3 shares

  + Demux :

  - Fix TTML entities not passed to decoder

  - Fixed some WebVTT styling tags being not applied

  - Misc raw H264/HEVC frame rate fixes

  - Fix adaptive regression on TS format change (mostly HLS)

  - Fixed MP4 regression with twos/sowt PCM audio

  - Fixed some MP4 raw quicktime and ms-PCM audio

  - Fixed MP4 interlacing handling

  - Multiple adaptive stack (DASH/HLS/Smooth) fixes

  - Enabled Live seeking for HLS

  - Fixed seeking in some cases for HLS

  - Improved Live playback for Smooth and DASH

  - Fixed adaptive unwanted end of stream in some cases

  - Faster adaptive start and new buffering control options

  + Packetizers :

  - Fixes H264/HEVC incomplete draining in some cases

  - packetizer_helper: Fix potential trailing junk on last
    packet

  - Added missing drain in packetizers that was causing
    missing last frame or audio

  - Improved check to prevent fLAC synchronization drops

  + Decoder :

  - avcodec: revector video decoder to fix incomplete drain

  - spudec: implemented palette updates, fixing missing
    subtitles on some DVD

  - Fixed WebVTT CSS styling not being applied on
    Windows/macOS

  - Fixed Hebrew teletext pages support in zvbi

  - Fixed Dav1d aborting decoding on corrupted picture

  - Extract and display of all CEA708 subtitles

  - Update libfaad to 2.9.1

  - Add DXVA support for VP9 Profile 2 (10 bits)

  - Mediacodec aspect ratio with Amazon devices

  + Audio output :

  - Added support for iOS audiounit audio above 48KHz

  - Added support for amem audio up to 384KHz

  + Video output :

  - Fix for opengl glitches in some drivers

  - Fix GMA950 opengl support on macOS

  - YUV to RGB StretchRect fixes with NVIDIA drivers

  - Use libpacebo new tone mapping desaturation algorithm

  + Text renderer :

  - Fix crashes on macOS with SSA/ASS subtitles containing
    emoji

  - Fixed unwanted growing background in Freetype rendering
    and Y padding

  + Mux: Fixed some YUV mappings

  + Service Discovery: Update libmicrodns to 0.1.2.

  + Misc :

  - Update YouTube, SoundCloud and Vocaroo scripts: this
    restores playback of YouTube URLs.

  - Add missing .wpl & .zpl file associations on Windows

  - Improved chromecast audio quality

Update to version 3.0.8 'vetinari' :

  + Fix stuttering for low framerate videos

  + Improve adaptive streaming

  + Improve audio output for external audio devices on
    macOS/iOS

  + Fix hardware acceleration with Direct3D11 for some AMD
    drivers

  + Fix WebVTT subtitles rendering

  + Vetinari is a major release changing a lot in the media
    engine of VLC. It is one of the largest release we've
    ever done. Notably, it :

  - activates hardware decoding on all platforms, of H.264 &
    H.265, 8 & 10bits, allowing 4K60 or even 8K decoding
    with little CPU consumption,

  - merges all the code from the mobile ports into the same
    codebase with common numbering and releases,

  - supports 360 video and 3D audio, and prepares for VR
    content,

  - supports direct HDR and HDR tone-mapping,

  - updates the audio passthrough for HD Audio codecs,

  - allows browsing of local network drives like SMB, FTP,
    SFTP, NFS...

  - stores the passwords securely,

  - brings a new subtitle rendering engine, supporting
    ComplexTextLayout and font fallback to support multiple
    languages and fonts,

  - supports ChromeCast with the new renderer framework,

  - adds support for numerous new formats and codecs,
    including WebVTT, AV1, TTML, HQX, 708, Cineform, and
    many more,

  - improves Bluray support with Java menus, aka BD-J,

  - updates the macOS interface with major cleaning and
    improvements,

  - support HiDPI UI on Windows, with the switch to Qt5,

  - prepares the experimental support for Wayland on Linux,
    and switches to OpenGL by default on Linux.

  + Security fixes included :

  - Fix a buffer overflow in the MKV demuxer
    (CVE-2019-14970)

  - Fix a read buffer overflow in the avcodec decoder
    (CVE-2019-13962)

  - Fix a read buffer overflow in the FAAD decoder

  - Fix a read buffer overflow in the OGG demuxer
    (CVE-2019-14437, CVE-2019-14438)

  - Fix a read buffer overflow in the ASF demuxer
    (CVE-2019-14776)

  - Fix a use after free in the MKV demuxer (CVE-2019-14777,
    CVE-2019-14778)

  - Fix a use after free in the ASF demuxer (CVE-2019-14533)

  - Fix a couple of integer underflows in the MP4 demuxer
    (CVE-2019-13602)

  - Fix a null dereference in the dvdnav demuxer

  - Fix a null dereference in the ASF demuxer
    (CVE-2019-14534)

  - Fix a null dereference in the AVI demuxer

  - Fix a division by zero in the CAF demuxer
    (CVE-2019-14498)

  - Fix a division by zero in the ASF demuxer
    (CVE-2019-14535)

  - Disbale mod-plug for the time being: libmodplug 0.8.9 is
    not yet available.

  - Disable SDL_image (SDL 1.2) based codec. It is only a
    wrapper around some image loading libraries (libpng,
    libjpeg, ...) which are either wrapped by vlc itself
    (libpng_plugin.so) or via libavcodec
    (libavcodec_plugin.so)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146428"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vlc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-codec-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-codec-gstreamer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-jack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-vdpau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-vdpau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/27");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libvlc5-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvlc5-debuginfo-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvlccore9-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvlccore9-debuginfo-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-codec-gstreamer-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-codec-gstreamer-debuginfo-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-debuginfo-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-debugsource-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-devel-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-jack-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-jack-debuginfo-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-lang-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-noX-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-noX-debuginfo-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-opencv-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-opencv-debuginfo-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-qt-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-qt-debuginfo-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-vdpau-3.0.9.2-lp151.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-vdpau-debuginfo-3.0.9.2-lp151.6.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvlc5 / libvlc5-debuginfo / libvlccore9 / libvlccore9-debuginfo / etc");
}
