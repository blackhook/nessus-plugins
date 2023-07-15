#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1118.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103658);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10371", "CVE-2017-7592", "CVE-2017-7593", "CVE-2017-7594", "CVE-2017-7595", "CVE-2017-7596", "CVE-2017-7597", "CVE-2017-7598", "CVE-2017-7599", "CVE-2017-7600", "CVE-2017-7601", "CVE-2017-7602", "CVE-2017-9403", "CVE-2017-9404");

  script_name(english:"openSUSE Security Update : tiff (openSUSE-2017-1118)");
  script_summary(english:"Check for the openSUSE-2017-1118 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tiff to version 4.0.8 fixes a several bugs and
security issues :

These security issues were fixed :

  - CVE-2017-7595: The JPEGSetupEncode function allowed
    remote attackers to cause a denial of service
    (divide-by-zero error and application crash) via a
    crafted image (bsc#1033127).

  - CVE-2016-10371: The TIFFWriteDirectoryTagCheckedRational
    function allowed remote attackers to cause a denial of
    service (assertion failure and application exit) via a
    crafted TIFF file (bsc#1038438).

  - CVE-2017-7598: Error in tif_dirread.c allowed remote
    attackers to cause a denial of service (divide-by-zero
    error and application crash) via a crafted image
    (bsc#1033118).

  - CVE-2017-7596: Undefined behavior because of floats
    outside their expected value range, which allowed remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    crafted image (bsc#1033126).

  - CVE-2017-7597: Undefined behavior because of floats
    outside their expected value range, which allowed remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    crafted image (bsc#1033120).

  - CVE-2017-7599: Undefined behavior because of shorts
    outside their expected value range, which allowed remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    crafted image (bsc#1033113).

  - CVE-2017-7600: Undefined behavior because of chars
    outside their expected value range, which allowed remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    crafted image (bsc#1033112).

  - CVE-2017-7601: Because of a shift exponent too large for
    64-bit type long undefined behavior was caused, which
    allowed remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted image (bsc#1033111).

  - CVE-2017-7602: Prevent signed integer overflow, which
    allowed remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted image (bsc#1033109).

  - CVE-2017-7592: The putagreytile function had a
    left-shift undefined behavior issue, which might allowed
    remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted image (bsc#1033131).

  - CVE-2017-7593: Ensure that tif_rawdata is properly
    initialized, to prevent remote attackers to obtain
    sensitive information from process memory via a crafted
    image (bsc#1033129).

  - CVE-2017-7594: The OJPEGReadHeaderInfoSecTablesDcTable
    function allowed remote attackers to cause a denial of
    service (memory leak) via a crafted image (bsc#1033128).

  - CVE-2017-9403: Prevent memory leak in function
    TIFFReadDirEntryLong8Array, which allowed attackers to
    cause a denial of service via a crafted file
    (bsc#1042805).

  - CVE-2017-9404: Fixed memory leak vulnerability in
    function OJPEGReadHeaderInfoSecTablesQTable, which
    allowed attackers to cause a denial of service via a
    crafted file (bsc#1042804).

These various other issues were fixed :

  - Fix uint32 overflow in TIFFReadEncodedStrip() that
    caused an integer division by zero. Reported by Agostino
    Sarubbo.

  - fix heap-based buffer overflow on generation of PixarLog
    / LUV compressed files, with ColorMap, TransferFunction
    attached and nasty plays with bitspersample. The fix for
    LUV has not been tested, but suffers from the same kind
    of issue of PixarLog.

  - modify ChopUpSingleUncompressedStrip() to instanciate
    compute ntrips as TIFFhowmany_32(td->td_imagelength,
    rowsperstrip), instead of a logic based on the total
    size of data. Which is faulty is the total size of data
    is not sufficient to fill the whole image, and thus
    results in reading outside of the
    StripByCounts/StripOffsets arrays when using
    TIFFReadScanline()

  - make OJPEGDecode() early exit in case of failure in
    OJPEGPreDecode(). This will avoid a divide by zero, and
    potential other issues.

  - fix misleading indentation as warned by GCC.

  - revert change done on 2016-01-09 that made Param member
    of TIFFFaxTabEnt structure a uint16 to reduce size of
    the binary. It happens that the Hylafax software uses
    the tables that follow this typedef (TIFFFaxMainTable,
    TIFFFaxWhiteTable, TIFFFaxBlackTable), although they are
    not in a public libtiff header.

  - add TIFFReadRGBAStripExt() and TIFFReadRGBATileExt()
    variants of the functions without ext, with an extra
    argument to control the stop_on_error behaviour.

  - fix potential memory leaks in error code path of
    TIFFRGBAImageBegin().

  - increase libjpeg max memory usable to 10 MB instead of
    libjpeg 1MB default. This helps when creating files with
    'big' tile, without using libjpeg temporary files.

  - add _TIFFcalloc()

  - return 0 in Encode functions instead of -1 when
    TIFFFlushData1() fails.

  - only run JPEGFixupTagsSubsampling() if the
    YCbCrSubsampling tag is not explicitly present. This
    helps a bit to reduce the I/O amount when the tag is
    present (especially on cloud hosted files).

  - in LZWPostEncode(), increase, if necessary, the code
    bit-width after flushing the remaining code and before
    emitting the EOI code.

  - fix memory leak in error code path of
    PixarLogSetupDecode().

  - fix potential memory leak in
    OJPEGReadHeaderInfoSecTablesQTable,
    OJPEGReadHeaderInfoSecTablesDcTable and
    OJPEGReadHeaderInfoSecTablesAcTable

  - avoid crash in Fax3Close() on empty file.

  - TIFFFillStrip(): add limitation to the number of bytes
    read in case td_stripbytecount[strip] is bigger than
    reasonable, so as to avoid excessive memory allocation.

  - fix memory leak when the underlying codec (ZIP,
    PixarLog) succeeds its setupdecode() method, but
    PredictorSetup fails.

  - TIFFFillStrip() and TIFFFillTile(): avoid excessive
    memory allocation in case of shorten files. Only
    effective on 64 bit builds and non-mapped cases.

  - TIFFFillStripPartial() / TIFFSeek(), avoid potential
    integer overflows with read_ahead in
    CHUNKY_STRIP_READ_SUPPORT mode.

  - avoid excessive memory allocation in case of shorten
    files. Only effective on 64 bit builds.

  - update tif_rawcc in CHUNKY_STRIP_READ_SUPPORT mode with
    tif_rawdataloaded when calling TIFFStartStrip() or
    TIFFFillStripPartial(). 

  - avoid potential int32 overflow in TIFFYCbCrToRGBInit()
    Fixes

  - avoid potential int32 overflows in multiply_ms() and
    add_ms().

  - fix out-of-buffer read in PackBitsDecode() Fixes

  - LogL16InitState(): avoid excessive memory allocation
    when RowsPerStrip tag is missing.

  - update dec_bitsleft at beginning of LZWDecode(), and
    update tif_rawcc at end of LZWDecode(). This is needed
    to properly work with the latest chnges in tif_read.c in
    CHUNKY_STRIP_READ_SUPPORT mode.

  - PixarLogDecode(): resync tif_rawcp with next_in and
    tif_rawcc with avail_in at beginning and end of
    function, similarly to what is done in LZWDecode().
    Likely needed so that it works properly with latest
    chnges in tif_read.c in CHUNKY_STRIP_READ_SUPPORT mode.

  - initYCbCrConversion(): add basic validation of luma and
    refBlackWhite coefficients (just check they are not NaN
    for now), to avoid potential float to int overflows.

  - _TIFFVSetField(): fix outside range cast of double to
    float.

  - initYCbCrConversion(): check luma[1] is not zero to
    avoid division by zero

  - _TIFFVSetField(): fix outside range cast of double to
    float.

  - initYCbCrConversion(): check luma[1] is not zero to
    avoid division by zero.

  - initYCbCrConversion(): stricter validation for
    refBlackWhite coefficients values.

  - avoid uint32 underflow in cpDecodedStrips that can cause
    various issues, such as buffer overflows in the library.

  - fix readContigStripsIntoBuffer() in -i (ignore) mode so
    that the output buffer is correctly incremented to avoid
    write outside bounds.

  - add 3 extra bytes at end of strip buffer in
    readSeparateStripsIntoBuffer() to avoid read outside of
    heap allocated buffer.

  - fix integer division by zero when BitsPerSample is
    missing.

  - fix NULL pointer dereference in -r mode when the image
    has no StripByteCount tag.

  - avoid potential division by zero is BitsPerSamples tag
    is missing.

  - when TIFFGetField(, TIFFTAG_NUMBEROFINKS, ) is called,
    limit the return number of inks to SamplesPerPixel, so
    that code that parses ink names doesn't go past the end
    of the buffer.

  - avoid potential division by zero is BitsPerSamples tag
    is missing.

  - fix uint32 underflow/overflow that can cause heap-based
    buffer overflow.

  - replace assert( (bps % 8) == 0 ) by a non assert check.

  - fix 2 heap-based buffer overflows (in PSDataBW and
    PSDataColorContig).

  - prevent heap-based buffer overflow in -j mode on a
    paletted image.

  - fix wrong usage of memcpy() that can trigger unspecified
    behaviour.

  - avoid potential invalid memory read in t2p_writeproc.

  - avoid potential heap-based overflow in
    t2p_readwrite_pdf_image_tile().

  - remove extraneous TIFFClose() in error code path, that
    caused double free.

  - error out cleanly in cpContig2SeparateByRow and
    cpSeparate2ContigByRow if BitsPerSample != 8 to avoid
    heap based overflow.

  - avoid integer division by zero.

  - call TIFFClose() in error code paths.

  - emit appropriate message if the input file is empty.

  - close TIFF handle in error code path.

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042805"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libtiff-devel-4.0.8-17.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtiff5-4.0.8-17.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtiff5-debuginfo-4.0.8-17.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tiff-4.0.8-17.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tiff-debuginfo-4.0.8-17.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tiff-debugsource-4.0.8-17.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.8-17.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtiff5-32bit-4.0.8-17.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.8-17.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtiff-devel-4.0.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtiff5-4.0.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtiff5-debuginfo-4.0.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tiff-4.0.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tiff-debuginfo-4.0.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tiff-debugsource-4.0.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtiff5-32bit-4.0.8-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.8-21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff-devel-32bit / libtiff-devel / libtiff5-32bit / libtiff5 / etc");
}
