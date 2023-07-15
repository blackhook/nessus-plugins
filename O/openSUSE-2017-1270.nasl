#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1270.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104528);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-7530", "CVE-2017-11446", "CVE-2017-11534", "CVE-2017-12428", "CVE-2017-12431", "CVE-2017-12433", "CVE-2017-13133", "CVE-2017-13139", "CVE-2017-15033");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2017-1270)");
  script_summary(english:"Check for the openSUSE-2017-1270 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

Security issues fixed :

  - CVE-2017-15033: A denial of service attack (memory leak)
    was fixed in ReadYUVImage in coders/yuv.c [bsc#1061873]

  - CVE-2017-11446: An infinite loop in ReadPESImage was
    fixed. (bsc#1049379)

  - CVE-2017-12433: A memory leak in ReadPESImage in
    coders/pes.c was fixed. (bsc#1052545)

  - CVE-2017-12428: A memory leak in ReadWMFImage in
    coders/wmf.c was fixed. (bsc#1052249)

  - CVE-2017-12431: A use-after-free in ReadWMFImage was
    fixed. (bsc#1052253)

  - CVE-2017-11534: A memory leak in the lite_font_map() in
    coders/wmf.c was fixed. (bsc#1050135)

  - CVE-2017-13133: A memory exhaustion in load_level
    function in coders/xcf.c was fixed. (bsc#1055219)

  - CVE-2017-13139: A out-of-bounds read in the
    ReadOneMNGImage was fixed. (bsc#1055430)

This update also reverts an incorrect fix for CVE-2016-7530
[bsc#1054924].

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061873"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/13");
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

if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-debuginfo-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-debugsource-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-devel-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-extra-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-extra-debuginfo-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-6_Q16-3-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-devel-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickCore-6_Q16-1-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickWand-6_Q16-1-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-PerlMagick-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-PerlMagick-debuginfo-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-debuginfo-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-debugsource-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-devel-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-extra-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-extra-debuginfo-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-6_Q16-3-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-devel-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickCore-6_Q16-1-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickWand-6_Q16-1-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-PerlMagick-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-PerlMagick-debuginfo-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-37.1") ) flag++;

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
