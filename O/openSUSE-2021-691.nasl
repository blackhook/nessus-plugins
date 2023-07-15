#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-691.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149579);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2020-26664");

  script_name(english:"openSUSE Security Update : vlc (openSUSE-2021-691)");
  script_summary(english:"Check for the openSUSE-2021-691 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for vlc fixes the following issues :

Update to version 3.0.13 :

  + Demux :

  - Adaptive: fix artefacts in HLS streams with wrong
    profiles/levels

  - Fix regression on some MP4 files for the audio track

  - Fix MPGA and ADTS probing in TS files

  - Fix Flac inside AVI files

  - Fix VP9/Webm artefacts when seeking

  + Codec :

  - Support SSA text scaling

  - Fix rotation on Android rotation

  - Fix WebVTT subtitles that start at 00:00

  + Access :

  - Update libnfs to support NFSv4

  - Improve SMB2 integration

  - Fix Blu-ray files using Unicode names on Windows

  - Disable mcast lookups on Android for RTSP playback

  + Video Output: Rework the D3D11 rendering wait, to fix
    choppiness on display

  + Interfaces :

  - Fix VLC getting stuck on close on X11 (#21875)

  - Improve RTL on preferences on macOS

  - Add mousewheel horizontal axis control

  - Fix crash on exit on macOS

  - Fix sizing of the fullscreen controls on macOS

  + Misc :

  - Improve MIDI fonts search on Linux

  - Update Soundcloud, Youtube, liveleak

  - Fix compilation with GCC11

  - Fix input-slave option for subtitles

  + Updated translations.

Update to version 3.0.12 :

  + Access: Add new RIST access module compliant with simple
    profile (VSF_TR-06-1).

  + Access Output: Add new RIST access output module
    compliant with simple profile (VSF_TR-06-1).

  + Demux: Fixed adaptive's handling of resolution settings.

  + Audio output: Fix audio distortion on macOS during start
    of playback.

  + Video Output: Direct3D11: Fix some potential crashes
    when using video filters.

  + Misc :

  - Several fixes in the web interface, including privacy
    and security improvements

  - Update YouTube and Vocaroo scripts.

  + Updated translations."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181918"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vlc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libvlc5-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvlc5-debuginfo-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvlccore9-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvlccore9-debuginfo-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-codec-gstreamer-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-codec-gstreamer-debuginfo-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-debuginfo-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-debugsource-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-devel-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-jack-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-jack-debuginfo-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-lang-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-noX-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-noX-debuginfo-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-opencv-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-opencv-debuginfo-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-qt-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-qt-debuginfo-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-vdpau-3.0.13-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vlc-vdpau-debuginfo-3.0.13-lp152.2.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvlc5 / libvlc5-debuginfo / libvlccore9 / libvlccore9-debuginfo / etc");
}
