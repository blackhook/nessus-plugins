#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-707.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149550);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-22204");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/01");

  script_name(english:"openSUSE Security Update : perl-Image-ExifTool (openSUSE-2021-707)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for perl-Image-ExifTool fixes the following issues :

Update to version 12.25 fixes (boo#1185547 CVE-2021-22204)

  - JPEG XL support is now official

  - Added read support for Medical Research Council (MRC)     image files

  - Added ability to write a number of 3gp tags in video     files

  - Added a new Sony PictureProfile value (thanks Jos Roost)

  - Added a new Sony LensType (thanks LibRaw)

  - Added a new Nikon LensID (thanks Niels Kristian Bech     Jensen)

  - Added a new Canon LensType

  - Decode more GPS information from Blackvue dashcam videos

  - Decode a couple of new NikonSettings tags (thanks Warren     Hatch)

  - Decode a few new RIFF tags

  - Improved Validate option to add minor warning if     standard XMP is missing xpacket wrapper

  - Avoid decoding some large arrays in DNG images to     improve performance unless the -m option is used

  - Patched bug that could give runtime warning when trying     to write an empty XMP structure

  - Fixed decoding of ImageWidth/Height for JPEG XL images

  - Fixed problem were Microsoft Xtra tags couldn't be     deleted

version 12.24 :

  - Added a new PhaseOne RawFormat value (thanks LibRaw)

  - Decode a new Sony tag (thanks Jos Roost)

  - Decode a few new Panasonic and FujiFilm tags (thanks     LibRaw and Greybeard)

  - Patched security vulnerability in DjVu reader

  - Updated acdsee.config in distribution (thanks StarGeek)

  - Recognize AutoCAD DXF files

  - More work on experimental JUMBF read support

  - More work on experimental JPEG XL read/write support

version 12.23 :

  - Added support for Olympus ORI files

  - Added experimental read/write support for JPEG XL images

  - Added experimental read support for JUMBF metadata in     JPEG and Jpeg2000 images

  - Added built-in support for parsing GPS track from Denver     ACG-8050 videos with the -ee option

  - Added a some new Sony lenses (thanks Jos Roost and     LibRaw)

  - Changed priority of Samsung trailer tags so the first     DepthMapImage takes precedence when -a is not used

  - Improved identification of M4A audio files

  - Patched to avoid escaping ',' in 'Binary data' message     when

    -struct is used

  - Removed Unknown flag from MXF VideoCodingSchemeID tag

  - Fixed -forcewrite=EXIF to apply to EXIF in binary header     of EPS files

  - API Changes :

  + Added BlockExtract option

version 12.22 :

  - Added a few new Sony LensTypes and a new SonyModelID     (thanks Jos Roost and LibRaw)

  - Added Extra BaseName tag

  - Added a new CanonModelID (thanks LibRaw)

  - Decode timed GPS from unlisted programs in M2TS videos     with the -ee3 option

  - Decode more Sony rtmd tags

  - Decode some tags for the Sony ILME-FX3 (thanks Jos     Roost)

  - Allow negative values to be written to XMP-aux:LensID

  - Recognize HEVC video program in M2TS files

  - Enhanced -b option so --b suppresses tags with binary     data

  - Improved flexibility when writing GPS coordinates :

  + Now pulls latitude and longitude from a combined     GPSCoordinates string

  + Recognizes the full word 'South' and 'West' to write     negative coordinates

  - Improved warning when trying to write an integer     QuickTime date/time tag and Time::Local is not available

  - Convert GPSSpeed from mph to km/h in timed GPS from     Garmin MP4 videos

version 12.21 :

  - Added a few new iOS QuickTime tags

  - Decode a couple more Sony rtmd tags

  - Patch to avoid possible 'Use of uninitialized value'     warning when attempting to write QuickTime date/time     tags with an invalid value

  - Fixed problem writing Microsoft Xtra tags

  - Fixed Windows daylight savings time patch for file times     that was broken in 12.19 (however directory times will     not yet handle DST properly)

version 12.20 :

  - Added ability to write some Microsoft Xtra tags in     MOV/MP4 videos

  - Added two new Canon LensType values (thanks Norbert     Wasser)

  - Added a new Nikon LensID

  - Fixed problem reading FITS comments that start before     column 11

version 12.19 :

  - Added -list_dir option

  - Added the 'ls-l' Shortcut tag

  - Extract Comment and History from FITS files

  - Enhanced FilePermissions to include device type (similar     to 'ls -l')

  - Changed the name of Apple ContentIdentifier tag to     MediaGroupUUID (thanks Neal Krawetz)

  - Fixed a potential 'substr outside of string' runtime     error when reading corrupted EXIF

  - Fixed edge case where NikonScanIFD may not be copied     properly when copying MakerNotes to another file

  - API Changes :

  + Added ability to read/write System tags of directories

  + Enhanced GetAllGroups() to support family 7 and take     optional ExifTool reference

  + Changed QuickTimeHandler option default to 1

version 12.18 :

  - Added a new SonyModelID

  - Decode a number of Sony tags for the ILCE-1 (thanks Jos     Roost)

  - Decode a couple of new Canon tags (thanks LibRaw)

  - Patched to read differently formatted UserData:Keywords     as written by iPhone

  - Patched to tolerate out-of-order Nikon MakerNote IFD     entries when obtaining tags necessary for decryption

  - Fixed a few possible Condition warnings for some     NikonSettings tags

version 12.17 :

  - Added a new Canon FocusMode value

  - Added a new FujiFilm FilmMode value

  - Added a number of new XMP-crs tags (thanks Herb)

  - Decode a new H264 MDPM tag

  - Allow non-conforming lower-case XMP boolean 'true' and     'false' values to be written, but only when print     conversion is disabled

  - Improved Validate option to warn about non-capitalized     boolean XMP values

  - Improved logic for setting GPSLatitude/LongitudeRef     values when writing

  - Changed -json and -php options so the -a option is     implied even without the -g option

  - Avoid extracting audio/video data from AVI videos when
    -ee

    -u is used

  - Patched decoding of Canon ContinuousShootingSpeed for     newer firmware versions of the EOS-1DXmkIII

  - Re-worked LensID patch of version 12.00 (github issue     #51)

  - Fixed a few typos in newly-added NikonSettings tags     (thanks Herb)

  - Fixed problem where group could not be specified for     PNG-pHYs tags when writing version 12.16 :

  - Extract another form of video subtitle text

  - Enhanced -ee option with -ee2 and -ee3 to allow parsing     of the H264 video stream in MP4 files

  - Changed a Nikon FlashMode value

  - Fixed problem that caused a failed DPX test on     Strawberry Perl

  - API Changes :

  + Enhanced ExtractEmbedded option

version 12.15 :

  - Added a couple of new Sony LensType values (thanks     LibRaw and Jos Roost)

  - Added a new Nikon FlashMode value (thanks Mike)

  - Decode NikonSettings (thanks Warren Hatch)

  - Decode thermal information from DJI RJPEG images

  - Fixed extra newline in -echo3 and -echo4 outputs added     in version 12.10

  - Fixed out-of-memory problem when writing some very large     PNG files under Windows

version 12.14 :

  - Added support for 2 more types of timed GPS in video     files (that makes 49 different formats now supported)

  - Added validity check for PDF trailer dictionary Size

  - Added a new Pentax LensType

  - Extract metadata from Jpeg2000 Association box

  - Changed -g:XX:YY and -G:XX:YY options to show empty     strings for non-existent groups

  - Patched to issue warning and avoid writing date/time     values with a zero month or day number

  - Patched to avoid runtime warnings if trying to set     FileName to an empty string

  - Fixed issue that could cause GPS test number 12 to fail     on some systems

  - Fixed problem extracting XML as a block from Jpeg2000     images, and extract XML tags in the XML group instead of     XMP

  - Update URL

update to 12.13 :

  - Add time zone automatically to most string-based     QuickTime date/time tags when writing unless the     PrintConv option is disabled

  - Added -i HIDDEN option to ignore files with names that     start with '.'

  - Added a few new Nikon ShutterMode values (thanks Jan     Skoda)

  - Added ability to write Google GCamera MicroVideo XMP     tags

  - Decode a new Sony tag (thanks LibRaw)

  - Changed behaviour when writing only pseudo tags to     return an error and avoid writing any other tags if     writing FileName fails

  - Print 'X image files read' message even if only 1 file     is read when at least one other file has failed the -if     condition

  - Added ability to geotag from DJI CSV log files

  - Added a new CanonModelID

  - Added a couple of new Sony LensType values (thanks     LibRaw)

  - Enhanced -csvDelim option to allow '\t', '
', '\r' and     '\\'

  - Unescape '\b' and '\f' in imported JSON values

  - Fixed bug introduced in 12.10 which generated a 'Not an     integer' warning when attempting to shift some QuickTime     date/time tags

  - Fixed shared-write permission problem with -@ argfile     when using -stay_open and a filename containing special     characters on Windows

  - Added -csvDelim option

  - Added new Canon and Olympus LensType values (thanks     LibRaw)

  - Added a warning if ICC_Profile is deleted from an image     (github issue #63)

  - EndDir() function for -if option now works when
    -fileOrder is used

  - Changed FileSize conversion to use binary prefixes since     that is how the conversion is currently done (eg. MiB     instead of MB)

  - Patched -csv option so columns aren't resorted when     using -G option and one of the tags is missing from a     file

  - Fixed incompatiblity with Google Photos when writing     UserData:GPSCoordinates to MP4 videos

  - Fixed problem where the tags available in a -p format     string were limited to the same as the -if[NUM] option     when NUM was specified

  - Fixed incorrect decoding of     SourceFileIndex/SourceDirectoryIndex for Ricoh models

Update to 12.10

  - Added -validate test for proper TIFF magic number in     JPEG EXIF header

  - Added support for Nikon Z7 LensData version 0801

  - Added a new XMP-GPano tag

  - Decode ColorData for the Canon EOS 1DXmkIII

  - Decode more tags for the Sony ILCE-7SM3

  - Automatically apply QuickTimeUTC option for CR3 files

  - Improved decoding of XAttrMDLabel from MacOS files

  - Ignore time zones when writing date/time values and     using the -d option

  - Enhanced -echo3 and -echo4 options to allow exit status     to be returned

  - Changed -execute so the -q option no longer suppresses     the '(ready)' message when a synchronization number is     used

  - Added ability to copy CanonMakerNotes from CR3 images to     other file types

  - Added read support for ON1 presets file (.ONP)

  - Added two new CanonModelID values

  - Added trailing '/' when writing QuickTime:GPSCoordinates

  - Added a number of new XMP-crs tags

  - Added a new Sony LensType (thanks Jos Roost)

  - Added a new Nikon Z lens (thanks LibRaw)

  - Added a new Canon LensType

  - Decode ColorData for Canon EOS R5/R6

  - Decode a couple of new HEIF tags

  - Decode FirmwareVersion for Canon M50

  - Improved decoding of Sony CreativeStyle tags

  - Improved parsing of Radiance files to recognize comments

  - Renamed GIF AspectRatio tag to PixelAspectRatio

  - Patched EndDir() feature so subdirectories are always     processed when -r is used (previously, EndDir() would     end processing of a directory completely)

  - Avoid loading GoPro module unnecessarily when reading     MP4 videos from some other cameras

  - Fixed problem with an incorrect naming of CodecID tags     in some MKV videos

  - Fixed verbose output to avoid 'adding' messages for     existing flattened XMP tags

  - Added a new Sony LensType

  - Recognize Mac OS X xattr files

  - Extract ThumbnailImage from MP4 videos of more dashcam     models

  - Improved decoding of a number of Sony tags

  - Fixed problem where the special -if EndDir() function     didn't work properly for directories after the one in     which it was initially called

  - Patched to read DLL files which don't have a .rsrc     section

  - Patched to support new IGC date format when geotagging

  - Patched to read DLL files with an invalid size in the     header 

  - Added support for GoPro .360 videos

  - Added some new Canon RF and Nikkor Z lenses

  - Added some new Sony LensType and CreativeStyle values     and decode some ILCE-7C tags

  - Added a number of new Olympus SceneMode values

  - Added a new Nikon LensID

  - Decode more timed metadata from Insta360 videos

  - Decode timed GPS from videos of more Garmin dashcam     models

  - Decode a new GoPro video tag

  - Reformat time-only EventTime values when writing and     prevent arbitrary strings from being written

  - Patched to accept backslashes in SourceFile entries for
    -csv option

update to 12.06

  - Added read support for Lyrics3 metadata (and fixed     problem where APE metadata may be ignored if Lyrics3     exists)

  - Added a new Panasonic VideoBurstMode value

  - Added a new Olympus MultipleExposureMode value

  - Added a new Nikon LensID

  - Added back conversions for XMP-dwc EventTime that were     removed in 12.04 with a patch to allow time-only values

  - Decode GIF AspectRatio

  - Decode Olympus FocusBracketStepSize

  - Extract PNG iDOT chunk in Binary format with the name     AppleDataOffsets

  - Process PNG images which do not start with mandatory     IHDR chunk

  - Added a new Panasonic SelfTimer value

  - Decode a few more DPX tags

  - Extract AIFF APPL tag as ApplicationData

  - Fixed bug writing QuickTime ItemList 'gnre' Genre values

  - Fixed an incorrect value for Panasonic     VideoBurstResolution

  - Fixed problem when applying a time shift to some invalid     makernote date/time values

update to 12.04 :

  - See /usr/share/doc/packages/perl-Image-ExifTool/Change 

update to 11.50, see Image-ExifTool-11.50.tar.gz for details

Update to version 11.30 :

  - Add a new Sony/Minolta LensType.

  - Decode streaming metadata from TomTom Bandit Action Cam     MP4 videos.

  - Decode Reconyx HF2 PRO maker notes.

  - Decode ColorData for some new Canon models.

  - Enhanced -geotag feature to set AmbientTemperature if     available.

  - Remove non-significant spaces from some DICOM values.

  - Fix possible ''x' outside of string' error when reading     corrupted EXIF.

  - Fix incorrect write group for GeoTIFF tags.

Update to version 11.29

  - See /usr/share/doc/packages/perl-Image-ExifTool/Changes

Update to version 11.27

  - See /usr/share/doc/packages/perl-Image-ExifTool/Changes

Update to version 11.24

  - See /usr/share/doc/packages/perl-Image-ExifTool/Changes

Update to version 11.11 (changes since 11.01) :

  - See /usr/share/doc/packages/perl-Image-ExifTool/Changes

Update to 11.01 :

  - Added a new ProfileCMMType

  - Added a Validate warning about non-standard EXIF or XMP     in PNG images

  - Added a new Canon LensType

  - Decode a couple more PanasonicRaw tags

  - Patched to avoid adding tags to QuickTime videos with     multiple 'mdat' atoms --> avoids potential corruption of     these videos!

Update to 11.00 :

  - Added read support for WTV and DVR-MS videos

  - Added print conversions for some ASF date/time tags

  - Added a new SonyModelID

  - Decode a new PanasonicRaw tag

  - Decode some new Sony RX100 VI tags

  - Made Padding and OffsetSchema tags 'unsafe' so they     aren't copied by default");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185547");
  script_set_attribute(attribute:"solution", value:
"Update the affected perl-Image-ExifTool packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22204");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ExifTool DjVu ANT Perl injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exiftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-File-RandomAccess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Image-ExifTool");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"exiftool-12.25-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-File-RandomAccess-12.25-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-Image-ExifTool-12.25-lp152.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exiftool / perl-File-RandomAccess / perl-Image-ExifTool");
}
