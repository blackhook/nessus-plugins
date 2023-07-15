#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-822.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150206);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2021-3185");

  script_name(english:"openSUSE Security Update : gstreamer / gstreamer-plugins-bad / gstreamer-plugins-base / etc (openSUSE-2021-822)");
  script_summary(english:"Check for the openSUSE-2021-822 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gstreamer, gstreamer-plugins-bad,
gstreamer-plugins-base, gstreamer-plugins-good, gstreamer-plugins-ugly
fixes the following issues :

gstreamer was updated to version 1.16.3 (bsc#1181255) :

  - delay creation of threadpools

  - bin: Fix `deep-element-removed` log message

  - buffer: fix meta sequence number fallback on rpi

  - bufferlist: foreach: always remove as parent if buffer
    is changed

  - bus: Make setting/replacing/clearing the sync handler
    thread-safe

  - elementfactory: Fix missing features in case a feature
    moves to another filename

  - element: When removing a ghost pad also unset its target

  - meta: intern registered impl string

  - registry: Use a toolchain-specific registry file on
    Windows

  - systemclock: Invalid internal time calculation causes
    non-increasing clock time on Windows

  - value: don't write to `const char *`

  - value: Fix segfault comparing empty GValueArrays

  - Revert floating enforcing

  - aggregator: fix iteration direction in skip_buffers

  - sparsefile: fix possible crash when seeking

  - baseparse: cache fix

  - baseparse: fix memory leak when subclass skips whole
    input buffer

  - baseparse: Set the private duration before posting a
    duration-changed message

  - basetransform: allow not passthrough if generate_output
    is implemented

  - identity: Fix a minor leak using meta_str

  - queue: protect against lost wakeups for iterm_del
    condition

  - queue2: Avoid races when posting buffering messages

  - queue2: Fix missing/dropped buffering messages at
    startup

  - identity: Unblock condition variable on FLUSH_START

  - check: Use `g_thread_yield()` instead of `g_usleep(1)`

  - tests: use cpu_family for arch checks

  - gst-launch: Follow up to missing `s/g_print/gst_print/g`

  - gst-inspect: Add define guard for
    `g_log_writer_supports_color()`

  - gst-launch: go back down to `GST_STATE_NULL` in one
    step.

  - device-monitor: list hidden providers before listing
    devices

  - autotools build fixes for GNU make 4.3

gstreamer-plugins-good was updated to version 1.16.3 (bsc#1181255) :

  - deinterlace: on-the-fly renegotiation

  - flacenc: Pass audio info from set_format() to
    query_total_samples() explicitly

  - flacparse: fix broken reordering of flac metadata

  - jack: Use jack_free(3) to release ports

  - jpegdec: check buffer size before dereferencing

  - pulse: fix discovery of newly added devices

  - qtdemux fuzzing fixes

  - qtdemux: Add 'mp3 ' fourcc that VLC seems to produce now

  - qtdemux: Specify REDIRECT information in error message

  - rtpbin: fix shutdown crash in rtpbin

  - rtpsession: rename RTCP thread

  - rtpvp8pay, rtpvp9pay: fix caps leak in set_caps()

  - rtpjpegdepay: outputs framed jpeg

  - rtpjitterbuffer: Properly free internal packets queue in
    finalize()

  - rtspsrc: Don't return TRUE for unhandled query

  - rtspsrc: Avoid stack overflow recursing waiting for
    response

  - rtspsrc: Use the correct type for storing the
    max-rtcp-rtp-time-diff property

  - rtspsrc: Error out when failling to receive message
    response

  - rtspsrc: Fix for segmentation fault when handling
    set/get_parameter requests

  - speex: Fix crash on Windows caused by cross-CRT issue

  - speexdec: Crash when stopping the pipeline

  - splitmuxsrc: Properly stop the loop if no part reader is
    present

  - use gst_element_class_set_metadata when passing dynamic
    strings

  - v4l2videodec: Increase internal bitstream pool size

  - v4l2: fix crash when handling unsupported video format

  - videocrop: allow properties to be animated by
    GstController

  - videomixer: Don't leak peer caps

  - vp8enc/vp8enc: set 1 for the default value of
    VP8E_SET_STATIC_THRESHOLD

  - wavenc: Fix writing of the channel mask with >2 channels

gstreamer-plugins-bad was updated to version 1.16.3 (bsc#1181255) :

  - amcvideodec: fix sync meta copying not taking a
    reference

  - audiobuffersplit: Perform discont tracking on running
    time

  - audiobuffersplit: Specify in the template caps that only
    interleaved audio is supported

  - audiobuffersplit: Unset DISCONT flag if not
    discontinuous

  - autoconvert: Fix lock-less exchange or free condition

  - autoconvert: fix compiler warnings with g_atomic on
    recent GLib versions

  - avfvideosrc: element requests camera permissions even
    with capture-screen property is true

  - codecparsers: h264parser: guard against ref_pic_markings
    overflow

  - dtlsconnection: Avoid segmentation fault when no srtp
    capabilities are negotiated

  - dtls/connection: fix EOF handling with openssl 1.1.1e

  - fdkaacdec: add support for mpegversion=2

  - hls: Check nettle version to ensure AES128 support

  - ipcpipeline: Rework compiler checks

  - interlace: Increment phase_index before checking if
    we're at the end of the phase

  - lv2: Make it build with -fno-common

  - h264parser: Do not allocate too large size of memory for
    registered user data SEI

  - ladspa: fix unbounded integer properties

  - modplug: avoid division by zero

  - msdkdec: Fix GstMsdkContext leak

  - msdkenc: fix leaks on windows

  - musepackdec: Don't fail all queries if no sample rate is
    known yet

  - openslessink: Allow openslessink to handle 48kHz
    streams.

  - opencv: allow compilation against 4.2.x

  - proxysink: event_function needs to handle the event when
    it is disconnecetd from proxysrc

  - vulkan: Drop use of VK_RESULT_BEGIN_RANGE

  - wasapi: added missing lock release in case of error in
    gst_wasapi_xxx_reset

  - wasapi: Fix possible deadlock while downwards state
    change

  - waylandsink: Clear window when pipeline is stopped

  - webrtc: Support non-trickle ICE candidates in the SDP

  - webrtc: Unmap all non-binary buffers received via the
    datachannel

  - meson: build with neon 0.31

  - Drop upstream fixed patch:
    gstreamer-h264parser-fix-overflow.patch

  - h264parser: guard against ref_pic_markings overflow
    (bsc#1181255 CVE-2021-3185)

  - Disable the kate/libtiger plugin. Kate streams for
    karaoke are not used anymore, and the source tarball for
    libtiger is no longer available upstream.
    (jsc#SLE-13843)

gstreamer-plugins-ugly was updated to version 1.16.3 (bsc#1181255) :

  + x264enc: corrected em_data value in CEA-708 CC SEI
    message

gstreamer-plugins-base was updated to version 1.16.3 (bsc#1181255) :

  - audioaggregator: Check all downstream allowed caps
    structures if they support the upstream rate

  - audioaggregator: Fix negotiation with downstream if
    there is no peer yet

  - audioencoder: fix segment event leak

  - discoverer: Fix caps handling in `pad-added` signal
    handler

  - discoverer: Start discovering next URI from right thread

  - fft: Update our kiss fft version, fixes thread-safety
    and concurrency issues and misc other things

  - gl: numerous memory fixes (use-after-free, leaks,
    missing NULL-ify)

  - gl/display/egl: ensure debug category is initialized

  - gstglwindow_x11: fix resize

  - pbutils: Add latest H.264 level values

  - rtpbuffer: fix header extension length validation

  - video: Fix NV12_64Z32 number of component

  - video-format: RGB16/15 are not 16 bit per component but
    only 5.333 and 5

  - video: fix top/bottom field flags

  - videodecoder: don't copy interlace-mode from reference
    state

  - appsrc/appsink: Make setting/replacing callbacks
    thread-safe

  - compositor: Fix checkerboard filling for BGRx/RGBx and
    UYVY/YUY2/YVYU

  - decodebin3: only force streams-selected seqnum after a
    select-streams

  - glupload: Fix fallback from direct dmabuf to dmabuf
    upload method

  - glvideomixer: perform `_get_highest_precision()` on the
    GL thread

  - libvisual: use `gst_element_class_set_metadata()` when
    passing dynamic strings

  - oggstream: Workaround for broken PAR in VP8 BOS

  - subparse: accept WebVTT timestamps without an hour
    component

  - playbin: Handle error message with redirection
    indication

  - textrender: Fix AYUV output.

  - typefind: Consider MPEG-PS PSM to be a PES type

  - uridecodebin3: default to non-0 buffer-size and
    buffer-duration, otherwise it could potentially cause
    big memory allocations over time

  - videoaggregator: Don't configure NULL
    chroma-site/colorimetry

  - videorate/videoscale/audioresample: Ensure that the caps
    returned from...

  - build: Replace bashisms in configure for Wayland and
    GLES3

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/SLE-13843"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected gstreamer / gstreamer-plugins-bad / gstreamer-plugins-base / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-chromaprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-chromaprint-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-chromaprint-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-chromaprint-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-fluidsynth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-fluidsynth-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-fluidsynth-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-fluidsynth-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-bad-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-base-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-extra-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-extra-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-jack-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-jack-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-jack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-qtqml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-good-qtqml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-ugly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-ugly-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-ugly-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-ugly-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-ugly-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-plugins-ugly-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gstreamer-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstadaptivedemux-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstadaptivedemux-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstadaptivedemux-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstadaptivedemux-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstallocators-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstallocators-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstallocators-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstallocators-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstapp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstapp-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstapp-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstapp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstaudio-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstaudio-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstaudio-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstaudio-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadaudio-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadaudio-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadaudio-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbadaudio-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstbasecamerabinsrc-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstcodecparsers-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstfft-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstfft-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstfft-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstfft-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstgl-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstgl-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstgl-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstgl-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstinsertbin-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstisoff-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstisoff-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstisoff-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstisoff-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstmpegts-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstpbutils-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstpbutils-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstpbutils-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstpbutils-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstphotography-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstplayer-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstplayer-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstplayer-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstplayer-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstreamer-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstreamer-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstreamer-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstreamer-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstriff-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstriff-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstriff-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstriff-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtp-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtp-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtsp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtsp-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtsp-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstrtsp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsctp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsctp-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsctp-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsctp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsdp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsdp-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsdp-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstsdp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsttag-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsttag-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsttag-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsttag-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgsturidownloader-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstvideo-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstvideo-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstvideo-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstvideo-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwayland-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwebrtc-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwebrtc-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwebrtc-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgstwebrtc-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Gst-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstAllocators-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstApp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstAudio-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstGL-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstInsertBin-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstMpegts-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstPbutils-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstPlayer-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstRtp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstRtsp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstSdp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstTag-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstVideo-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GstWebRTC-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-debugsource-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-devel-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-lang-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-bad-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-bad-chromaprint-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-bad-chromaprint-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-bad-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-bad-debugsource-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-bad-devel-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-bad-fluidsynth-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-bad-fluidsynth-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-bad-lang-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-base-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-base-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-base-debugsource-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-base-devel-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-base-lang-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-debugsource-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-extra-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-extra-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-gtk-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-gtk-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-jack-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-jack-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-lang-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-qtqml-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-good-qtqml-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-ugly-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-ugly-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-ugly-debugsource-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-plugins-ugly-lang-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-utils-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gstreamer-utils-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstadaptivedemux-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstadaptivedemux-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstallocators-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstallocators-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstapp-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstapp-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstaudio-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstaudio-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstbadaudio-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstbadaudio-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstbasecamerabinsrc-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstbasecamerabinsrc-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstcodecparsers-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstcodecparsers-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstfft-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstfft-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstgl-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstgl-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstinsertbin-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstinsertbin-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstisoff-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstisoff-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstmpegts-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstmpegts-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstpbutils-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstpbutils-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstphotography-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstphotography-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstplayer-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstplayer-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstreamer-1_0-0-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstreamer-1_0-0-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstriff-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstriff-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstrtp-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstrtp-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstrtsp-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstrtsp-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstsctp-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstsctp-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstsdp-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstsdp-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgsttag-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgsttag-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgsturidownloader-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgsturidownloader-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstvideo-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstvideo-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstwayland-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstwayland-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstwebrtc-1_0-0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgstwebrtc-1_0-0-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-Gst-1_0-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstAllocators-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstApp-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstAudio-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstGL-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstInsertBin-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstMpegts-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstPbutils-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstPlayer-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstRtp-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstRtsp-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstSdp-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstTag-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstVideo-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GstWebRTC-1_0-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-32bit-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-32bit-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-bad-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-bad-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-bad-chromaprint-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-bad-chromaprint-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-bad-fluidsynth-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-bad-fluidsynth-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-base-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-base-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-base-devel-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-good-32bit-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-good-32bit-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-good-extra-32bit-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-good-extra-32bit-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-good-jack-32bit-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-good-jack-32bit-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-ugly-32bit-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gstreamer-plugins-ugly-32bit-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstadaptivedemux-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstadaptivedemux-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstallocators-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstallocators-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstbadaudio-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstbadaudio-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstbasecamerabinsrc-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstbasecamerabinsrc-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstcodecparsers-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstcodecparsers-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstfft-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstfft-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstgl-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstgl-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstinsertbin-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstinsertbin-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstisoff-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstisoff-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstmpegts-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstmpegts-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstphotography-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstphotography-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstplayer-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstplayer-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstreamer-1_0-0-32bit-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstreamer-1_0-0-32bit-debuginfo-1.16.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstriff-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstriff-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstrtp-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstrtp-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstrtsp-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstrtsp-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstsctp-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstsctp-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstsdp-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstsdp-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgsturidownloader-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgsturidownloader-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstwayland-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstwayland-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstwebrtc-1_0-0-32bit-1.16.3-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgstwebrtc-1_0-0-32bit-debuginfo-1.16.3-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-bad / gstreamer-plugins-bad-chromaprint / etc");
}
