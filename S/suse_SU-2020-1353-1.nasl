#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1353-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(136800);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/30");

  script_cve_id("CVE-2018-6942");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : freetype2 (SUSE-SU-2020:1353-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for freetype2 to version 2.10.1 fixes the following 
issues :

Security issue fixed :

CVE-2018-6942: Fixed a NULL pointer dereference within ttinerp.c
(bsc#1079603).

Non-security issues fixed :

Update to version 2.10.1

  - The bytecode hinting of OpenType variation fonts was
    flawed, since the data in the `CVAR' table wasn't
    correctly applied.

  - Auto-hinter support for Mongolian.

  - The handling of the default character in PCF fonts as
    introduced in version 2.10.0 was partially broken,
    causing premature abortion of charmap iteration for many
    fonts.

  - If `FT_Set_Named_Instance' was called with the same
    arguments twice in a row, the function returned an
    incorrect error code the second time.

  - Direct rendering using FT_RASTER_FLAG_DIRECT crashed
    (bug introduced in version 2.10.0).

  - Increased precision while computing OpenType font
    variation instances.

  - The flattening algorithm of cubic Bezier curves was
    slightly changed to make it faster. This can cause very
    subtle rendering changes, which aren't noticeable by the
    eye, however.

  - The auto-hinter now disables hinting if there are blue
    zones defined for a `style' (i.e., a certain combination
    of a script and its related typographic features) but
    the font doesn't contain any characters needed to set up
    at least one blue zone.

Add tarball signatures and freetype2.keyring

Update to version 2.10.0

  - A bunch of new functions has been added to access and
    process COLR/CPAL data of OpenType fonts with
    color-layered glyphs.

  - As a GSoC 2018 project, Nikhil Ramakrishnan completely
    overhauled and modernized the API reference.

  - The logic for computing the global ascender, descender,
    and height of OpenType fonts has been slightly adjusted
    for consistency.

  - `TT_Set_MM_Blend' could fail if called repeatedly with
    the same arguments.

  - The precision of handling deltas in Variation Fonts has
    been increased.The problem did only show up with
    multidimensional designspaces.

  - New function `FT_Library_SetLcdGeometry' to set up the
    geometry of LCD subpixels.

  - FreeType now uses the `defaultChar' property of PCF
    fonts to set the glyph for the undefined character at
    glyph index 0 (as FreeType already does for all other
    supported font formats). As a consequence, the order of
    glyphs of a PCF font if accessed with FreeType can be
    different now compared to previous versions. This change
    doesn't affect PCF font access with cmaps.

  - `FT_Select_Charmap' has been changed to allow parameter
    value `FT_ENCODING_NONE', which is valid for BDF, PCF,
    and Windows FNT formats to access built-in cmaps that
    don't have a predefined `FT_Encoding' value.

  - A previously reserved field in the `FT_GlyphSlotRec'
    structure now holds the glyph index.

  - The usual round of fuzzer bug fixes to better reject
    malformed fonts.

  - `FT_Outline_New_Internal' and `FT_Outline_Done_Internal'
    have been removed.These two functions were public by
    oversight only and were never documented.

  - A new function `FT_Error_String' returns descriptions of
    error codes if configuration macro
    FT_CONFIG_OPTION_ERROR_STRINGS is defined.

  - `FT_Set_MM_WeightVector' and `FT_Get_MM_WeightVector'
    are new functions limited to Adobe MultiMaster fonts to
    directly set and get the weight vector.

Enable subpixel rendering with infinality config :

Re-enable freetype-config, there is just too many fallouts.

Update to version 2.9.1

  - Type 1 fonts containing flex features were not rendered
    correctly (bug introduced in version 2.9).

  - CVE-2018-6942: Older FreeType versions can crash with
    certain malformed variation fonts.

  - Bug fix: Multiple calls to `FT_Get_MM_Var' returned
    garbage.

  - Emboldening of bitmaps didn't work correctly sometimes,
    showing various artifacts (bug introduced in version
    2.8.1).

  - The auto-hinter script ranges have been updated for
    Unicode 11. No support for new scripts have been added,
    however, with the exception of Georgian Mtavruli.

freetype-config is now deprecated by upstream and not enabled by
default.

Update to version 2.10.1

  - The `ftmulti' demo program now supports multiple hidden
    axes with the same name tag.

  - `ftview', `ftstring', and `ftgrid' got a `-k' command
    line option to emulate a sequence of keystrokes at
    start-up.

  - `ftview', `ftstring', and `ftgrid' now support screen
    dumping to a PNG file.

  - The bytecode debugger, `ttdebug', now supports variation
    TrueType fonts; a variation font instance can be
    selected with the new `-d' command line option.

Add tarball signatures and freetype2.keyring

Update to version 2.10.0

  - The `ftdump' demo program has new options `-c' and `-C'
    to display charmaps in compact and detailed format,
    respectively. Option `-V' has been removed.

  - The `ftview', `ftstring', and `ftgrid' demo programs use
    a new command line option `-d' to specify the program
    window's width, height, and color depth.

  - The `ftview' demo program now displays red boxes for
    zero-width glyphs.

  - `ftglyph' has limited support to display fonts with
    color-layered glyphs.This will be improved later on.

  - `ftgrid' can now display bitmap fonts also.

  - The `ttdebug' demo program has a new option `-f' to
    select a member of a TrueType collection (TTC).

  - Other various improvements to the demo programs.

Remove 'Supplements: fonts-config' to avoid accidentally pulling in Qt
dependencies on some non-Qt based desktops.(bsc#1091109) fonts-config
is fundamental but ft2demos seldom installs by end users. only
fonts-config maintainers/debuggers may use ft2demos along to debug
some issues.

Update to version 2.9.1

  - No changelog upstream.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6942/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201353-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36ee49be"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-1353=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6942");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freetype2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freetype2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreetype6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreetype6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libfreetype6-32bit-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libfreetype6-32bit-debuginfo-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"freetype2-debugsource-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"freetype2-devel-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libfreetype6-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libfreetype6-debuginfo-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libfreetype6-32bit-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libfreetype6-32bit-debuginfo-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"freetype2-debugsource-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"freetype2-devel-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libfreetype6-2.10.1-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libfreetype6-debuginfo-2.10.1-4.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype2");
}
