#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-173.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106891);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-6360");

  script_name(english:"openSUSE Security Update : mpv (openSUSE-2018-173)");
  script_summary(english:"Check for the openSUSE-2018-173 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mpv fixes the following issues :

MPV was updated to version 0.27.2

Security issues fixed :

  - CVE-2018-6360: Additional fix for where mpv allowed
    remote attackers to execute arbitrary code via a crafted
    website, because it read HTML documents containing VIDEO
    elements, and accepts arbitrary URLs in a src attribute
    without a protocol whitelist in
    player/lua/ytdl_hook.lua. For example, an
    av://lavfi:ladspa=file= URL signifies that the product
    should call dlopen on a shared object file located at an
    arbitrary local pathname. The issue exists because the
    product does not consider that youtube-dl can provide a
    potentially unsafe URL. (boo#1077894)

Fixes and minor enhancements :

  - ytdl_hook: whitelist subtitle URLs as well (#5456)

MPV was updated to version 0.27.1

Security issues fixed :

  - CVE-2018-6360: mpv allowed remote attackers to execute
    arbitrary code via a crafted website, because it read
    HTML documents containing VIDEO elements, and accepts
    arbitrary URLs in a src attribute without a protocol
    whitelist in player/lua/ytdl_hook.lua. For example, an
    av://lavfi:ladspa=file= URL signifies that the product
    should call dlopen on a shared object file located at an
    arbitrary local pathname. The issue exists because the
    product does not consider that youtube-dl can provide a
    potentially unsafe URL. (boo#1077894)

Fixes and minor enhancements :

  - ytdl_hook: whitelist protocols from urls retrieved from
    youtube-dl (#5456)

Version 0.27.0 :

Added features :

  - libmpv: options: add a thread-safe way to notify option
    updates

  - vd_lavc/vo_opengl: support embedded ICC profiles

  - vo: rendering API abstraction for future non-GL video
    outputs

  - vo_opengl: add a gamut warning feature to highlight
    out-of-gamut colors (--gamut-warning)

  - vo_opengl: add direct rendering support (--vd-lavc-dr)

  - vo_opengl: implement (faster) compute shader based EWA
    kernel

  - vo_opengl: implement HLG OOTF inverse

  - vo_opengl: support HDR peak detection
    (--hdr-compute-peak)

  - vo_opengl: support float input pixel formats

  - vo_opengl: support loading custom user textures (#4586)

  - vo_opengl: support user compute shaders Removed 
features :

  - Remove video equalizer handling from vo_direct3d,
    vo_sdl, vo_vaapi, and vo_xv (GPL, not worth the effort
    to support legacy VOs) Added options and commands :

  - player: add --track-auto-selection option Changed
    options and commands :

  - input: use mnemonic names for mouse buttons, same as Qt:
    https://doc.qt.io/qt-5/qt.html#MouseButton-enum

  - options: change --loop semantics

  - player: make --lavfi-complex changeable at runtime

  - vf_eq: remove this filter (GPL; uses libavfilter&rsquo;s
    eq filter now, with changed semantics)

  - video: change --deinterlace behavior

  - vo_opengl: generalize HDR tone mapping to gamut mapping,

    --hdr-tone-mapping &rarr; --tone-mapping Removed options
    and commands :

  - --field-dominance (GPL-only author, no chance of
    relicensing)

  - input: drop deprecated 'osd' command

  - options: drop --video-aspect-method=hybrid (GPL-only)
    Fixes and minor enhancements :

  - TOOLS/autocrop.lua: fix cropdetect black limit for
    10-bit videos

  - TOOLS/lua/autodeint: update to lavfi-bridge

  - TOOLS/lua/status-line: improve and update

  - af_lavrresample: don't call swr_set_compensation()
    unless necessary (#4716)

  - ao_oss: fix period_size calculation (#4642)

  - ao_rsound: allow setting the host

  - audio: fix spdif mode

  - filter_kernels: correct spline64 kernel

  - options: fix --include (#4673)

  - player: fix --end with large values (#4650)

  - player: fix confusion in audio resync code (#4688)

  - player: make refresh seeks slightly more robust (#4757)

  - player: readd smi subtitle extension (#4626)

  - vd_lavc: change auto-probe order to prefer cuda over
    vdpau-copy

  - vd_lavc: fix device leak with copy-mode hwaccels (#4735)

  - vd_lavc: fix hwdec compatibility with yuvj420p formats

  - vd_lavc: fix mid-stream hwdec fallback

  - vf_vapoursynth: fix inverted sign and restore 10 bit
    support (#4720)

  - video: increase --monitorpixelaspect range

  - vo_opengl: adjust the rules for linearization (#4631)

  - vo_opengl: scale deband-grain to the signal range

  - vo_opengl: tone map on the maximum signal component

  - x11: fix that window could be resized when using
    embedding (#4784)

  - ytdl_hook: resolve relative paths when joining segment
    urls (#4827)

  - ytdl_hook: support fragments with relative paths, fixes
    segmented DASH

Version 0.26.0 :

  - Built-in V4L TV support is disabled by default.
    av://v4l2 can be used instead.

  - Support for C plugins is now enabled by default (#4491).

  - Many more parts of the player are now licensed under
    LGPL, see Copyright file.

Added features :

  - csputils: implement sony s-gamut

  - vo_opengl: add new HDR tone mapping algorithm (mobius,
    now default)

  - vo_opengl: hwdec_cuda: Support separate decode and
    display devices

  - vo_opengl: implement sony s-log1 and s-log2 trc

  - vo_opengl: implement support for OOTFs and non-display
    referred content

Removed features :

  - vf_dlopen: remove this filter

Added options and commands :

  - vo_opengl: add --tone-mapping-desaturate

  - vo_opengl: support tone-mapping-param for `clip`

  - ytdl_hook: add option to exclude URLs from being parsed

Changed options and commands :

  - allow setting profile option with libmpv

  - audio: move replaygain control to top-level options

  - external_files: parse ~ in --(sub,audio)-paths

  - options: change --sub-fix-timing default to no (#4484)

  - options: expose string list actions for --sub-file
    option

  - options: slight cleanup of --sub-ass-style-override

  + signfs &rarr; scale

  + --sub-ass-style-override &rarr; --sub-ass-override

  - renamed the HDR TRCs `st2084` and `std-b67` to `pq` and
    `hlg` respectively

  - replace vf_format's `peak` suboption by `sig-peak`,
    which is relative to the reference white level instead
    of in cd/m^2

  - the following options change to append-by-default (and
    possibly separator): --script

  - video: change --video-aspect-method default value to
    `container`

Deprecated options and commands :

  - m_option: deprecate multiple items for -add etc.

  - player: deprecate 'osd' command

  - --audio-file-paths => --audio-file-path

  - --sub-paths => --sub-file-path

  - --opengl-shaders => --opengl-shader

  - --sub-paths => --sub-file-paths

  - the following options are deprecated for setting via 
API :

  + 'script' (use 'scripts')

  + 'sub-file' (use 'sub-files')

  + 'audio-file' (use 'audio-files')

  + 'external-file' (use 'external-files') (the
    compatibility hacks for this will be removed after this
    release)

Removed options and commands :

  - chmap: remove misleading 'downmix' channel layout name
    (#4545)

  - demux_lavf: remove --demuxer-lavf-cryptokey option
    (#4579)

  - input.conf: drop TV/DVB bindings

  - options: remove remaining deprecated audio device
    selection options

  + --alsa-device

  + --oss-device

  + --coreaudio-exclusive

  + --pulse-sink

  + --rsound-host/--rsound-port

  + --ao-sndio-device

  + --ao-wasapi-exclusive

  + --ao-wasapi-device

  - remove option --target-brightness

  - remove property 'video-params/nom-peak'

Fixes and minor enhancements :

  - TOOLS/lua/autoload.lua: actually sort files case
    insensitive (#4398)

  - TOOLS/lua/autoload.lua: ignores all files starting with
    '.'

  - ao_pulse: reorder format choice to prefer float and S32
    over S16 as fallback format

  - command: add missing change notification for
    playlist-shuffle (#4573)

  - demux_disc: fix bluray subtitle language retrieval
    (#4611)

  - demux_mkv: fix alpha with vp9 + libvpx

  - demux_mkv: support FFmpeg A_MS/ACM extensions

  - ipc-unix: don&rsquo;t truncate the message on EAGAIN
    (#4452)

  - ipc: raise json nesting limit (#4394)

  - mpv_identify: replace deprecated fps property (#4550)

  - options/path: fallback to USERPROFILE if HOME isn't set

  - player: close audio device on no audio track

  - player: fix potential segfault when playing dvd:// with
    DVD disabled (#4393)

  - player: prevent seek position to jump around adjacent
    keyframes, e.g. when dragging the OSC bar on short
    videos (#4183)

  - vo_opengl: bump up SHADER_MAX_HOOKS and
    MAX_TEXTURE_HOOKS to 64

  - vo_opengl: correct off-by-one in scale=oversample

  - vo_opengl: do not use vaapi-over-GLX (#4555)

  - vo_opengl: fall back to ordered dither instead of
    blowing up (#4519)

  - vo_opengl: tone map in linear XYZ instead of RGB

  - x11: add 128x128 sized icon support

  - ytdl_hook: add a header to support geo-bypass

  - ytdl_hook: don't override start time set by saved state

  - ytdl_hook: don't override user-set start time

  - ytdl_hook: treat single-entry playlists as a single
    video

  - gen: make output reproducible by ensuring stable output
    of pairs() by wrapping it where it matters. (Closes #18)
    version 3.3.15

  - Fix af/vf filter argument expansion (#15)

  - Remove some invalid suggestions for some options (#14)

  - Recognize all --profile-style options as such and
    complete them version 3.3.14

  - Reflect changed --list-options output for --vf-add-style
    options

  - Let mpv own /etc/mpv/scripts as a ghost dir so other
    packages can create it and install scripts there."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://doc.qt.io/qt-5/qt.html#MouseButton-enum"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mpv packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpv1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpv-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libmpv1-0.27.2-13.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmpv1-debuginfo-0.27.2-13.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpv-0.27.2-13.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpv-bash-completion-3.3.16-13.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpv-debuginfo-0.27.2-13.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpv-devel-0.27.2-13.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpv-zsh-completion-0.27.2-13.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmpv1 / libmpv1-debuginfo / mpv / mpv-bash-completion / etc");
}
