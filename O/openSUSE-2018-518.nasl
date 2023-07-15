#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-518.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110213);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : GraphicsMagick (openSUSE-2018-518)");
  script_summary(english:"Check for the openSUSE-2018-518 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GraphicsMagick was updated to 1.3.29 :

  - Security Fixes :

  - GraphicsMagick is now participating in Google's oss-fuzz
    project 

  - JNG: Require that the embedded JPEG image have the same
    dimensions as the JNG image as provided by JHDR. Avoids
    a heap write overflow.

  - MNG: Arbitrarily limit the number of loops which may be
    requested by the MNG LOOP chunk to 512 loops, and
    provide the '-define mng:maximum-loops=value' option in
    case the user wants to change the limit. This fixes a
    denial of service caused by large LOOP specifications.

  - Bug fixes :

  - DICOM: Pre/post rescale functions are temporarily
    disabled (until the implementation is fixed).

  - JPEG: Fix regression in last release in which reading
    some JPEG files produces the error 'Improper call to
    JPEG library in state 201'.

  - ICON: Some DIB-based Windows ICON files were reported as
    corrupt to an unexpectedly missing opacity mask image.

  - In-memory Blob I/O: Don't implicitly increase the
    allocation size due to seek offsets.

  - MNG: Detect and handle failure to allocate global PLTE.
    Fix divide by zero.

  - DrawGetStrokeDashArray(): Check for failure to allocate
    memory.

  - BlobToImage(): Now produces useful exception reports to
    cover the cases where 'magick' was not set and the file
    format could not be deduced from its header.

  - API Updates :

  - Wand API: Added MagickIsPaletteImage(),
    MagickIsOpaqueImage(), MagickIsMonochromeImage(),
    MagickIsGrayImage(), MagickHasColormap() based on
    contributions by Troy Patteson.

  - New structure ImageExtra added and Image 'clip_mask'
    member is replaced by 'extra' which points to private
    ImageExtra allocation. The ImageGetClipMask() function
    now provides access to the clip mask image.

  - New structure DrawInfoExtra and DrawInfo 'clip_path' is
    replaced by 'extra' which points to private
    DrawInfoExtra allocation. The DrawInfoGetClipPath()
    function now provides access to the clip path.

  - New core library functions: GetImageCompositeMask(),
    CompositeMaskImage(), CompositePathImage(),
    SetImageCompositeMask(), ImageGetClipMask(),
    ImageGetCompositeMask(), DrawInfoGetClipPath(),
    DrawInfoGetCompositePath()

  - Deprecated core library functions:
    RegisterStaticModules(), UnregisterStaticModules().

  - Feature improvements :

  - Static modules (in static library or shared library
    without dynamically loadable modules) are now
    lazy-loaded using the same external interface as the
    lazy-loader for dynamic modules. This results in more
    similarity between the builds and reduces the fixed
    initialization overhead by only initializing the modules
    which are used.

  - SVG: The quality of SVG support has been significantly
    improved due to the efforts of Greg Wolfe.

  - FreeType/TTF rendering: Rendering fixes for opacity."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094352"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GraphicsMagick packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick3-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/30");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"GraphicsMagick-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"GraphicsMagick-debuginfo-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"GraphicsMagick-debugsource-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"GraphicsMagick-devel-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick++-Q16-12-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick++-Q16-12-debuginfo-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick++-devel-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick-Q16-3-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick-Q16-3-debuginfo-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick3-config-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagickWand-Q16-2-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagickWand-Q16-2-debuginfo-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-GraphicsMagick-1.3.29-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-GraphicsMagick-debuginfo-1.3.29-lp150.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / GraphicsMagick-debuginfo / etc");
}
