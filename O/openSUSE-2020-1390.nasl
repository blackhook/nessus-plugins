#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1390.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140681);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2020-15395");

  script_name(english:"openSUSE Security Update : libmediainfo / mediainfo (openSUSE-2020-1390)");
  script_summary(english:"Check for the openSUSE-2020-1390 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libmediainfo, mediainfo fixes the following issues :

libmediainfo was updated to version 20.08 :

Added :

  - MPEG-H 3D Audio full featured support (group presets,
    switch groups, groups, signal groups)

  - MP4/MOV: support of more metadata locations

  - JSON and XML outputs: authorize 'complete' output

  - MPEG-4: support of TrueHD

  - WM: show legacy value of performer if not same as modern
    one

  - WAV: trace of adtl (Associated Data List) chunk

Fixed :

  - URL encoding detection fix for URL having a query part
    (issue with e.g. pre-signed AWS S3 URLs)

  - Don't try to seek to the end (false positive range
    related error with HTTP)

  - DPX: don't load the whole file in RAM

  - Opus: fix wrong channel mapping

  - Miscellaneous other bug fixes

version 20.03

Added features :

  - AC-4 full featured support (presentations, groups,
    substreams)

  - MPEG-H 3D Audio basic support

  - MPEG-TS: audio preselection descriptor support

  - Dolby Vision v2 detection

  - MPEG-4: support of colr/nclx (color information) box

Bugs fixed :

  - URL encoding option fixes, permitting to use URL encoded
    or non URL encoded links

  - AAC: fix SBR frequency when in ADIF

  - DPX: ColorimetricSpecification and
    TransferCharacteristic were inverted

  - Some API calls were not thread safe

  - Several crash and memory leaks fixes

version 19.09

Added :

  - AC-4: basic detection, raw, in MP4 or TS

  - AC-3/E-AC-3: display time code of the first frame

  - Don't show anymore by default 'encoded' bit rates and
    stream sizes

  - MOV: Decode more language codes

Corrections :

  - MXF: some metadata were missing

  - AC-3: AC-3 actually has no bit depth, removing the
    default 16 value

  - AC-3/E-AC-3: fix bitrate info (so duration) with streams
    having a time code

  - AC-3: parse more frames also when in MP4, in order to
    better detect JOC (Atmos)

  - MP4: do not show audio bit depth if it is the 'default'
    16 (value is not trustable enough)

  - ProRes RAW: we know only width and height

  - SubRip: bad handling of files having a quote character

version 19.07

Added :

  - Dolby E: readout of Dolby E program description

  - MXF: Detection of Dolby Vision

  - MP4: support of Spatial Audio Metadata

  - DV: color space is explicit

  - DV: audio format settings

  - Matroska: PCM bit rate

  - MOV, MXF: Time code frame rate

  - DV: DVCAM commercial name for locked audio and PAL 4:2:0

  - MXF: Time code track name

Corrections :

  - USAC: frame rate was missing in case of non standard
    sampling rate

  - USAC: fix infinite loop with some LATM streams

  - WAV: MP3 delay should be added to BWF time reference

  - TTML: fix wrong output with standalone files

  - N19/STL: fix crash with some uncommon framerates

  - VC-3: fix sub sampling with some v2 files

  - DV: Time code frame number was wrong (divided by 2) for
    50/60 fps content

version 19.04

Added :

  - USAC: DRC effect types, Sample peak level, True peak
    level, Program loudness

  - HDR: SMPTE ST 2094 App 4 (including HDR10+) support

  - HDR: move HDR10, Dolby Vision and SL-HDR meta to
    specific generic 'HDR Format' lines

  - Matroska: SMPTE ST 2086 (HDR10) support

  - Matroska: FieldOrder support

  - HEIF image format support

  - AV1: support of AV1 in MP4, HEIF, IVF

  - MOV: Add a lot more countries to AppleStoreCountry field
    internal list

  - MXF: Fix memory leak when fully parsing big file with
    acquisition metadata

  - HEVC: more HEVC profiles (Multiview, Scalable, Screen
    Content...)

  - AAC: better handling of corrupted streams

  - AAC: better handling of unknown channel layouts

  - AVC in MP4: better support of corrupted streams

Corrected :

  - B1101, AVI: fix crash with some invalid streams

  - B1101, SMPTE ST 337: fix crash with some invalid streams

  - Matroska: chapters timestamp were not display if
    chapters have no name

  - MXF: Fix false positive truncated file detection when
    there is no Random Index Pack

  - AAC: channel layout typos (Rls instead of Lrs, Lr
    instead of Rb)

  - ProRes: correctly show color space if alpha plane is
    present

  - MPEG Audio: some VBR files use 'Info' Xing header, so we
    ignore the difference between 'Info' and 'Xing'

  - I943, MPEG-4: wrong display aspect ratio in some corner
    cases (32-bit release only)

  - I1096, OGG: assign METADATA_BLOCK_PICTURE tag to cover

  - I339, text in square brackets stripped in $if() section

version 18.12

Added features :

  - DCP: support of multi-reel packages

  - EBUCore: added some FFV1 related metadata

  - JPEG: better info display of CYMK files

  - Provide source of the color related metadata (container
    or stream) (hidden by default)

  - MXF: display more information when wrapper/essence
    values are detected as not same

  - MXF: ProRes profiles

  - MPEG-4: ProRes RAW support

  - MPEG-TS: add support of parsing some ETSI TS 103-433
    messages Bug fixes :

  - MPEG-2 Video: variable GOP detection fix

  - MPEG-7 export: some fields were missing due to the
    removal of some legacy fields

  - ADTS: Fix display of channel count for 8-channel streams

  - ID3v2: fix some date related issues

  - I298, ID3v2: fix wrong read of recording date in some
    cases

  - I1032, PBCore2: fix essenceFrameSize with non Video
    tracks

  - I1096, JPEG: fix crash with one file

  - Several other crash and memory leak fixes

version 18.08.1

  - Fix XML/MPEG-7/PBCore2 output discarding non ANSI
    characters

version 18.08

Added features :

  - Dolby Atmos (in E-AC-3 or TrueHD): support of bed
    channel count/configuration + objects count + complexity
    index

  - AC-3/DTS/AAC: display of info about legacy decoders
    behavior removed

  - AC-3/DTS/AAC: some changes in how format is displayed

  - AC-3/DTS/AAC: better split between technical names and
    commercial names

  - AAC: support of profile information from MP4_IOD_Tag
    AudioProfileLevelIndication

  - USAC (xHE-AAC) support

  - Audio channel layout: using a new terminology, better
    suited for 3D Audio, see
    https://mediaarea.net/AudioChannelLayout

  - DSD (DSF & DSDIFF) support

  - DXD (Digital eXtreme Definition) commercial name

  - Dolby Vision: use new form for profile (numbers instead
    of acronyms)

  - New format 'Directory' when image sequence + audio file
    is detected (1 directory style for the moment)

  - PBCore2 export update, thanks to WGBH

  - MPEG-7 export update

  - NISO export update

  - AV1: support of AOmedia AV1 based on 1.0.0
    specifications

  - ATRAC9 detection

  - Versionned RPMs

  - HEVC: better support of buggy SEI

  - ADTS: CodecID

  - Support of injection of external metadata

  - HTTPS: support of AWS extension 'x-amz-*' in HTTPS
    headers, permitting to manage temporary credentials
    (AssumeRole)

  - MPEG-4, #1005: Obey edit list in QuickTime Timecode
    track

Bug corrections :

  - MIXML: hide fields which were hidden in normal output

  - Hybrid AC-3/E-AC-3 (in Blu-rays): bit rate info was
    wrong

  - Lot of bug fixes, see full log for more info

version 18.05

Added :

  - PBCore 2.1 export update, sponsored by WGBH as part of
    the NEH-funded PBCore Development and Preservation
    Project

  - TIFF: more IFDs are supported (density, software...)

  - NISO Z39.87 output

Fixed :

  - Mastering Display Color Primaries: was always showing
    BT.709 instead of real value, when present

  - Attachments: do not provide anymore attachments content
    in XML by default, fixes

mediainfo was updated to version 20.08 :

Added :

  - MPEG-H 3D Audio full featured support (group presets,
    switch groups, groups, signal groups)

  - MP4/MOV: support of more metadata locations

  - JSON and XML outputs: authorize 'complete' output

  - MPEG-4: support of TrueHD

  - WM: show legacy value of performer if not same as modern
    one

  - WAV: trace of adtl (Associated Data List) chunk

Fixed :

  - URL encoding detection fix for URL having a query part
    (issue with e.g. pre-signed AWS S3 URLs)

  - Don't try to seek to the end (false positive range
    related error with HTTP)

  - DPX: don't load the whole file in RAM

  - Opus: fix wrong channel mapping

  - Miscellaneous other bug fixes

version 20.03

Added features :

  - AC-4 full featured support (presentations, groups,
    substreams)

  - MPEG-H 3D Audio basic support

  - MPEG-TS: audio preselection descriptor support

  - Dolby Vision v2 detection

  - MPEG-4: support of colr/nclx (color information) box

Bugs fixed :

  - URL encoding option fixes, permitting to use URL encoded
    or non URL encoded links

  - AAC: fix SBR frequency when in ADIF

  - DPX: ColorimetricSpecification and
    TransferCharacteristic were inverted

  - Several crash and memory leaks fixes

version 19.09

Added :

  - AC-4: basic detection, raw, in MP4 or TS

  - AC-3/E-AC-3: display time code of the first frame

  - Don't show anymore by default 'encoded' bit rates and
    stream sizes

  - MOV: Decode more language codes

Corrections :

  - MXF: some metadata were missing

  - AC-3: AC-3 actually has no bit depth, removing the
    default 16 value

  - AC-3/E-AC-3: fix bitrate info (so duration) with streams
    having a time code

  - AC-3: parse more frames also when in MP4, in order to
    better detect JOC (Atmos)

  - MP4: do not show audio bit depth if it is the 'default'
    16 (value is not trustable enough)

  - ProRes RAW: we know only width and height

  - SubRip: bad handling of files having a quote character

version 19.07

Added :

  - Dolby E: readout of Dolby E program description

  - MXF: Detection of Dolby Vision

  - MP4: support of Spatial Audio Metadata

  - DV: color space is explicit

  - DV: audio format settings

  - Matroska: PCM bit rate

  - MOV, MXF: Time code frame rate

  - DV: DVCAM commercial name for locked audio and PAL 4:2:0

  - MXF: Time code track name

Corrected :

  - USAC: frame rate was missing in case of non standard
    sampling rate

  - USAC: fix infinite loop with some LATM streams

  - WAV: MP3 delay should be added to BWF time reference

  - TTML: fix wrong output with standalone files

  - N19/STL: fix crash with some uncommon framerates

  - VC-3: fix sub sampling with some v2 files

  - DV: Time code frame number was wrong (divided by 2) for
    50/60 fps content

version 19.04

Added :

  - USAC: DRC effect types, Sample peak level, True peak
    level, Program loudness

  - HDR: SMPTE ST 2094 App 4 (including HDR10+) support

  - HDR: move HDR10, Dolby Vision and SL-HDR meta to
    specific generic 'HDR Format' lines

  - Matroska: SMPTE ST 2086 (HDR10) support

  - Matroska: FieldOrder support

  - HEIF image format support

  - AV1: support of AV1 in MP4, HEIF, IVF

  - MOV: Add a lot more countries to AppleStoreCountry field
    internal list

  - MXF: Fix memory leak when fully parsing big file with
    acquisition metadata

  - HEVC: more HEVC profiles (Multiview, Scalable, Screen
    Content...)

  - AAC: better handling of corrupted streams

  - AAC: better handling of unknown channel layouts

  - AVC in MP4: better support of corrupted streams

Changed :

  - B1101, AVI: fix crash with some invalid streams

  - B1101, SMPTE ST 337: fix crash with some invalid streams

  - Matroska: chapters timestamp were not display if
    chapters have no name

  - MXF: Fix false positive truncated file detection when
    there is no Random Index Pack

  - AAC: channel layout typos (Rls instead of Lrs, Lr
    instead of Rb)

  - ProRes: correctly show color space if alpha plane is
    present

  - MPEG Audio: some VBR files use 'Info' Xing header, so we
    ignore the difference between 'Info' and 'Xing'

  - I943, MPEG-4: wrong display aspect ratio in some corner
    cases (32-bit release only)

  - I1096, OGG: assign METADATA_BLOCK_PICTURE tag to cover

version 18.12

Added features :

  - DCP: support of multi-reel packages

  - EBUCore: added some FFV1 related metadata

  - JPEG: better info display of CYMK files

  - Provide source of the color related metadata (container
    or stream) (hidden by default)

  - MXF: display more information when wrapper/essence
    values are detected as not same

  - MXF: ProRes profiles

  - MPEG-4: ProRes RAW support

  - MPEG-TS: add support of parsing some ETSI TS 103-433
    messages

Bug fixes :

  - MPEG-2 Video: variable GOP detection fix

  - MPEG-7 export: some fields were missing due to the
    removal of some legacy fields

  - ADTS: Fix display of channel count for 8-channel streams

  - ID3v2: fix some date related issues

  - I298, ID3v2: fix wrong read of recording date in some
    cases

  - I1032, PBCore2: fix essenceFrameSize with non Video
    tracks

  - I1096, JPEG: fix crash with one file

  - Several other crash and memory leak fixes

version 18.08.1

  - Fix XML/MPEG-7/PBCore2 output discarding non ANSI
    characters

version 18.08

Added features :

  - Dolby Atmos (in E-AC-3 or TrueHD): support of bed
    channel count/configuration + objects count + complexity
    index

  - AC-3/DTS/AAC: display of info about legacy decoders
    behavior removed

  - AC-3/DTS/AAC: some changes in how format is displayed

  - AC-3/DTS/AAC: better split between technical names and
    commercial names

  - AAC: support of profile information from MP4_IOD_Tag
    AudioProfileLevelIndication

  - USAC (xHE-AAC) support

  - Audio channel layout: using a new terminology, better
    suited for 3D Audio, see
    https://mediaarea.net/AudioChannelLayout

  - DSD (DSF & DSDIFF) support

  - DXD (Digital eXtreme Definition) commercial name

  - Dolby Vision: use new form for profile (numbers instead
    of acronyms)

  - New format 'Directory' when image sequence + audio file
    is detected (1 directory style for the moment)

  - PBCore2 export update, thanks to WGBH

  - MPEG-7 export update

  - NISO export update

  - AV1: support of AOmedia AV1 based on 1.0.0
    specifications

  - ATRAC9 detection

  - Versionned RPMs

  - HEVC: better support of buggy SEI

  - ADTS: CodecID

  - Support of injection of external metadata

  - HTTPS: support of AWS extension 'x-amz-*' in HTTPS
    headers, permitting to manage temporary credentials
    (AssumeRole)

  - MPEG-4, #1005: Obey edit list in QuickTime Timecode
    track

Bug corrections :

  - MIXML: hide fields which were hidden in normal output

  - Hybrid AC-3/E-AC-3 (in Blu-rays): bit rate info was
    wrong

  - Lot of bug fixes, see full log for more info

version 18.05

Added :

  - PBCore 2.1 export update, sponsored by WGBH as part of
    the NEH-funded PBCore Development and Preservation
    Project

  - TIFF: more IFDs are supported (density, software...)

  - NISO Z39.87 output

Fixed :

  - Mastering Display Color Primaries: was always showing
    BT.709 instead of real value, when present

  - Attachments: do not provide anymore attachments content
    in XML by default, fixes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mediaarea.net/AudioChannelLayout"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libmediainfo / mediainfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kf5-mediainfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmediainfo0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mediainfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mediainfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mediainfo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mediainfo-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mediainfo-gui-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/21");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libmediainfo-debugsource-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libmediainfo-devel-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libmediainfo0-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libmediainfo0-debuginfo-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"kf5-mediainfo-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libmediainfo0-32bit-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libmediainfo0-32bit-debuginfo-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"mediainfo-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"mediainfo-debuginfo-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"mediainfo-debugsource-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"mediainfo-gui-20.08-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"mediainfo-gui-debuginfo-20.08-lp152.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmediainfo-debugsource / libmediainfo-devel / libmediainfo0 / etc");
}
