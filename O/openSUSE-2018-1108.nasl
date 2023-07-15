#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1108.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117975);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-16323", "CVE-2018-16328", "CVE-2018-16329", "CVE-2018-16413", "CVE-2018-16640", "CVE-2018-16641", "CVE-2018-16642", "CVE-2018-16643", "CVE-2018-16644", "CVE-2018-16645");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2018-1108)");
  script_summary(english:"Check for the openSUSE-2018-1108 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following security issues :

  - CVE-2018-16413: Prevent heap-based buffer over-read in
    the PushShortPixel function leading to DoS (bsc#1106989)

  - CVE-2018-16329: Prevent NULL pointer dereference in the
    GetMagickProperty function leading to DoS (bsc#1106858).

  - CVE-2018-16328: Prevent NULL pointer dereference exists
    in the CheckEventLogging function leading to DoS
    (bsc#1106857).

  - CVE-2018-16323: ReadXBMImage left data uninitialized
    when processing an XBM file that has a negative pixel
    value. If the affected code was used as a library loaded
    into a process that includes sensitive information, that
    information sometimes can be leaked via the image data
    (bsc#1106855)

  - CVE-2018-16642: The function InsertRow allowed remote
    attackers to cause a denial of service via a crafted
    image file due to an out-of-bounds write (bsc#1107616)

  - CVE-2018-16640: Prevent memory leak in the function
    ReadOneJNGImage (bsc#1107619)

  - CVE-2018-16641: Prevent memory leak in the
    TIFFWritePhotoshopLayers function (bsc#1107618).

  - CVE-2018-16643: The functions ReadDCMImage,
    ReadPWPImage, ReadCALSImage, and ReadPICTImage did check
    the return value of the fputc function, which allowed
    remote attackers to cause a denial of service via a
    crafted image file (bsc#1107612)

  - CVE-2018-16644: Added missing check for length in the
    functions ReadDCMImage and ReadPICTImage, which allowed
    remote attackers to cause a denial of service via a
    crafted image (bsc#1107609)

  - CVE-2018-16645: Prevent excessive memory allocation
    issue in the functions ReadBMPImage and ReadDIBImage,
    which allowed remote attackers to cause a denial of
    service via a crafted image file (bsc#1107604)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107619"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-7_Q16HDRI4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-7_Q16HDRI4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-7_Q16HDRI4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-7_Q16HDRI4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-7_Q16HDRI6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-7_Q16HDRI6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-7_Q16HDRI6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-7_Q16HDRI6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-7_Q16HDRI6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-7_Q16HDRI6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-7_Q16HDRI6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-7_Q16HDRI6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-debuginfo-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-debugsource-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-devel-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-extra-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-extra-debuginfo-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagick++-devel-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-PerlMagick-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-PerlMagick-debuginfo-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ImageMagick-devel-32bit-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-debuginfo-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagick++-devel-32bit-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-7.0.7.34-lp150.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-lp150.2.15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-debuginfo / ImageMagick-debugsource / etc");
}
