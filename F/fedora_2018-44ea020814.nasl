#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-44ea020814.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120384);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-4022");
  script_xref(name:"FEDORA", value:"2018-44ea020814");

  script_name(english:"Fedora 29 : mkvtoolnix (2018-44ea020814)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"# Version 28.2.0 'The Awakening' 2018-10-25

## Bug fixes

  - mkvmerge, mkvinfo, mkvextract, mkvpropedit, MKVToolNix
    GUI's info tool & chapter editor: fixed a case of memory
    being accessed after it had been freed earlier. This can
    be triggered by specially crafted Matroska files and
    lead to arbitrary code execution. The vulnerability was
    reported as Cisco TALOS 2018-0694 on 2018-10-25.

# Version 28.1.0 'Morning Child' 2018-10-23

## Bug fixes

  - mkvmerge: AV1 parser: fixed an error in the sequence
    header parser if neither the
    `reduced_still_picture_header` nor the
    `frame_id_numbers_present_flag` is set. Part of the fix
    for #2410.

  - mkvmerge: AV1 parser: when creating the `av1C` structure
    for the Codec Private element the sequence header OBU
    wasn't copied completely: its common data (type field &
    OBU size among others) was missing. Part of the fix for
    #2410.

  - mkvmerge: Matroska reader, AV1: mkvmerge will try to
    re-create the `av1C` data stored in Codec Private when
    reading AV1 from Matroska or WebM files created by
    mkvmerge v28.0.0. Part of the fix for #2410.

  - MKVToolNix GUI: info tool: the tool will no longer stop
    scanning elements when an EBML Void element is found
    after the first Cluster element. Fixes #2413.

# Version 28.0.0 'Voice In My Head' 2018-10-20

## New features and enhancements

  - mkvmerge: AV1 parser: updated the code for the finalized
    AV1 bitstream specification. Part of the implementation
    of #2261.

  - mkvmerge: AV1 packetizer: updated the code for the
    finalized AV1-in-Matroska & WebM mapping specification.
    Part of the implementation of #2261.

  - mkvmerge: AV1 support: the `--engage enable_av1` option
    has been removed again. Part of the implementation of
    #2261.

  - mkvmerge: MP4 reader: added support for AV1. Part of the
    implementation of #2261.

  - mkvmerge: DTS: implemented dialog normalization gain
    removal for extension substreams. Implements #2377.

  - mkvmerge, mkvextract: simple text subtitles: added a
    workaround for simple text subtitle tracks that don't
    contain a duration. Implements #2397.

  - mkvextract: added support for extracting AV1 to IVF.
    Part of the implementation of #2261.

  - mkvextract: IVF extractor (AV1, VP8, VP9): precise
    values will be used for the frame rate numerator &
    denominator header fields for certain well-known values
    of the track's default duration.

  - mkvmerge: VP9: mkvmerge will now create codec private
    data according to the VP9 codec mapping described in the
    WebM specifications. Implements #2379.

  - MKVToolNix GUI: automatic scaling for high DPI displays
    is activated if the GUI is compiled with Qt &ge; 5.6.0.
    Fixes #1996 and #2383.

  - MKVToolNix GUI: added a menu item ('Help' &rarr; 'System
    information') for displaying information about the
    system MKVToolNix is running on in order to make
    debugging easier.

  - MKVToolNix GUI: multiplexer, header editor: the user can
    enter a list of predefined track names in the
    preferences. She can later select from them in 'track
    name' combo box. Implements #2230.

## Bug fixes

  - mkvmerge: JSON identification: fixed a bug when removing
    invalid UTF-8 data from strings before they're output as
    JSON. Fixes #2398.

  - mkvmerge: MP4/QuickTime reader: fixed handling of PCM
    audio with FourCC `in24`. Fixes #2391.

  - mkvmerge: MPEG transport stream reader, teletext
    subtitles: the decision whether or not to keep frames
    around in order to potentially merge them with the
    following frame is made sooner. That avoids problems if
    there are large gaps between teletext subtitle frames
    which could lead to frames being interleaved too late.
    Fixes #2393.

  - mkvextract: IVF extractor (AV1, VP8, VP8): the frame
    rate header fields weren't clamped to 16 bits properly
    causing wrong frame rates to be written in certain
    situations.

  - mkvpropedit, MKVToolNix GUI's header editor: fixed file
    corruption when a one-byte space must be covered with a
    new EBML void element but all surrounding elements have
    a 'size length' field that's eight bytes long already.
    Fixes #2406.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-44ea020814"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mkvtoolnix package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mkvtoolnix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"mkvtoolnix-28.2.0-1.fc29")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mkvtoolnix");
}
