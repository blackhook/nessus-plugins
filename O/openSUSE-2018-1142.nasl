#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1142.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118066);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2018-1142)");
  script_summary(english:"Check for the openSUSE-2018-1142 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

  - Allow writing PS, PS2, PS3, XPS, EPS and PDF, disable
    reading these filetypes only by default security policy
    (bsc#1105592)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105592"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/11");
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

if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-debuginfo-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-debugsource-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-devel-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-extra-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-extra-debuginfo-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagick++-devel-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-PerlMagick-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-PerlMagick-debuginfo-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ImageMagick-devel-32bit-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-debuginfo-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagick++-devel-32bit-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-7.0.7.34-lp150.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-lp150.2.18.1") ) flag++;

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
