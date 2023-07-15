#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1197.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118219);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-13058", "CVE-2018-12599", "CVE-2018-12600", "CVE-2018-17965", "CVE-2018-17966", "CVE-2018-18016", "CVE-2018-18024");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2018-1197)");
  script_summary(english:"Check for the openSUSE-2018-1197 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

Security issues fixed :

  - CVE-2018-18024: Fixed an infinite loop in the
    ReadBMPImage function of the coders/bmp.c file. Remote
    attackers could leverage this vulnerability to cause a
    denial of service via a crafted bmp file. (bsc#1111069)

  - CVE-2018-18016: Fixed a memory leak in WritePCXImage
    (bsc#1111072).

  - CVE-2018-17965: Fixed a memory leak in WriteSGIImage
    (bsc#1110747).

  - CVE-2018-17966: Fixed a memory leak in WritePDBImage
    (bsc#1110746).

  - CVE-2018-12600: ReadDIBImage and WriteDIBImage allowed
    attackers to cause an out of bounds write via a crafted
    file. (bsc#1098545)

  - CVE-2018-12599: ReadBMPImage and WriteBMPImage allowed
    attackers to cause an out of bounds write via a crafted
    file. (bsc#1098546)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111072"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/19");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-debuginfo-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-debugsource-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-devel-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-extra-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-extra-debuginfo-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-6_Q16-3-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-devel-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickCore-6_Q16-1-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickWand-6_Q16-1-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-PerlMagick-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-PerlMagick-debuginfo-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-73.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-73.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-debuginfo / ImageMagick-debugsource / etc");
}
