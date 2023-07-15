#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-14.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(132905);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/17");

  script_cve_id("CVE-2019-11037");

  script_name(english:"openSUSE Security Update : php7-imagick (openSUSE-2020-14)");
  script_summary(english:"Check for the openSUSE-2020-14 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php7-imagick fixes the following issues :

Upgrade to version 3.4.4 :

Added :

  - function Imagick::optimizeImageTransparency()

  - METRIC_STRUCTURAL_SIMILARITY_ERROR

  - METRIC_STRUCTURAL_DISSIMILARITY_ERROR

  - COMPRESSION_ZSTD - https://github.com/facebook/zstd

  - COMPRESSION_WEBP

  - CHANNEL_COMPOSITE_MASK

  - FILTER_CUBIC_SPLINE - 'Define the lobes with the -define
    filter:lobes=(2,3,4) (reference
    https://imagemagick.org/discourse-server/viewtopic.php?f
    =2&t=32506).'

  - Imagick now explicitly conflicts with the Gmagick
    extension.

Fixes :

  - Correct version check to make RemoveAlphaChannel and
    FlattenAlphaChannel be available when using Imagick with
    ImageMagick version 6.7.8-x

  - Bug 77128 - Imagick::setImageInterpolateMethod() not
    available on Windows

  - Prevent memory leak when ImagickPixel::__construct
    called after object instantiation.

  - Prevent segfault when ImagickPixel internal constructor
    not called.

  - Imagick::setResourceLimit support for values larger than
    2GB (2^31) on 32bit platforms.

  - Corrected memory overwrite in
    Imagick::colorDecisionListImage()

  - Bug 77791 - ImagickKernel::fromMatrix() out of bounds
    write. Fixes CVE-2019-11037, boo#1135418

The following functions have been deprecated :

  - ImagickDraw, matte

  - Imagick::averageimages

  - Imagick::colorfloodfillimage

  - Imagick::filter

  - Imagick::flattenimages

  - Imagick::getimageattribute

  - Imagick::getimagechannelextrema

  - Imagick::getimageclipmask

  - Imagick::getimageextrema

  - Imagick::getimageindex

  - Imagick::getimagematte

  - Imagick::getimagemattecolor

  - Imagick::getimagesize

  - Imagick::mapimage

  - Imagick::mattefloodfillimage

  - Imagick::medianfilterimage

  - Imagick::mosaicimages

  - Imagick::orderedposterizeimage

  - Imagick::paintfloodfillimage

  - Imagick::paintopaqueimage

  - Imagick::painttransparentimage

  - Imagick::radialblurimage

  - Imagick::recolorimage

  - Imagick::reducenoiseimage

  - Imagick::roundcornersimage

  - Imagick::roundcorners

  - Imagick::setimageattribute

  - Imagick::setimagebias

  - Imagick::setimageclipmask

  - Imagick::setimageindex

  - Imagick::setimagemattecolor

  - Imagick::setimagebiasquantum

  - Imagick::setimageopacity

  - Imagick::transformimage"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/facebook/zstd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://imagemagick.org/discourse-server/viewtopic.php?f=2&t=32506"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php7-imagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-imagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-imagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/15");
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

if ( rpm_check(release:"SUSE15.1", reference:"php7-imagick-3.4.4-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-imagick-debuginfo-3.4.4-lp151.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-imagick-debugsource-3.4.4-lp151.8.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php7-imagick / php7-imagick-debuginfo / php7-imagick-debugsource");
}
