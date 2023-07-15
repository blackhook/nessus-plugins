#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-606.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149533);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2021-20309", "CVE-2021-20311", "CVE-2021-20312", "CVE-2021-20313");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2021-606)");
  script_summary(english:"Check for the openSUSE-2021-606 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ImageMagick fixes the following issues :

  - CVE-2021-20309: Division by zero in WaveImage() of
    MagickCore/visual-effects. (bsc#1184624)

  - CVE-2021-20311: Division by zero in sRGBTransformImage()
    in MagickCore/colorspace.c (bsc#1184626)

  - CVE-2021-20312: Integer overflow in WriteTHUMBNAILImage
    of coders/thumbnail.c (bsc#1184627)

  - CVE-2021-20313: Cipher leak when the calculating
    signatures in TransformSignatureof
    MagickCore/signature.c (bsc#1184628)

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184628"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20313");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-config-7-SUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-config-7-upstream");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
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

if ( rpm_check(release:"SUSE15.2", reference:"ImageMagick-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ImageMagick-config-7-SUSE-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ImageMagick-config-7-upstream-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ImageMagick-debuginfo-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ImageMagick-debugsource-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ImageMagick-devel-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ImageMagick-extra-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ImageMagick-extra-debuginfo-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libMagick++-devel-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-PerlMagick-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-PerlMagick-debuginfo-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"ImageMagick-devel-32bit-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-debuginfo-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libMagick++-devel-32bit-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-7.0.7.34-lp152.12.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-lp152.12.15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-config-7-SUSE / etc");
}
