#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2519.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131115);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2019-14980", "CVE-2019-14981", "CVE-2019-15139", "CVE-2019-15140", "CVE-2019-15141", "CVE-2019-16708", "CVE-2019-16709", "CVE-2019-16710", "CVE-2019-16711", "CVE-2019-16712", "CVE-2019-16713");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2019-2519)");
  script_summary(english:"Check for the openSUSE-2019-2519 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

Security issues fixed :

  - CVE-2019-15139: Fixed a denial-of-service vulnerability
    in ReadXWDImage (bsc#1146213).

  - CVE-2019-15140: Fixed a use-after-free bug in the Matlab
    image parser (bsc#1146212).

  - CVE-2019-15141: Fixed a divide-by-zero vulnerability in
    the MeanShiftImage function (bsc#1146211).

  - CVE-2019-14980: Fixed an application crash resulting
    from a heap-based buffer over-read in WriteTIFFImage
    (bsc#1146068).

  - CVE-2019-14981: Fixed a use after free in the UnmapBlob
    function (bsc#1146065).

  - CVE-2019-16708: Fixed a memory leak in magick/xwindow.c
    (bsc#1151781).

  - CVE-2019-16709: Fixed a memory leak in coders/dps.c
    (bsc#1151782).

  - CVE-2019-16710: Fixed a memory leak in coders/dot.c
    (bsc#1151783).

  - CVE-2019-16711: Fixed a memory leak in
    Huffman2DEncodeImage in coders/ps2.c (bsc#1151784).

  - CVE-2019-16712: Fixed a memory leak in
    Huffman2DEncodeImage in coders/ps3.c (bsc#1151785).

  - CVE-2019-16713: Fixed a memory leak in coders/dot.c
    (bsc#1151786).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151786"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-config-7-SUSE-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-config-7-upstream-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-debuginfo-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-debugsource-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-devel-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-extra-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ImageMagick-extra-debuginfo-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagick++-devel-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-PerlMagick-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-PerlMagick-debuginfo-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ImageMagick-devel-32bit-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-debuginfo-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagick++-devel-32bit-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-7.0.7.34-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-lp150.2.41.1") ) flag++;

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
