#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-36.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106065);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000445", "CVE-2017-1000476", "CVE-2017-11449", "CVE-2017-11751", "CVE-2017-12430", "CVE-2017-12642", "CVE-2017-14249", "CVE-2017-17680", "CVE-2017-17882", "CVE-2017-9409");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2018-36)");
  script_summary(english:"Check for the openSUSE-2018-36 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes several issues.

These security issues were fixed :

  - CVE-2017-1000476: A CPU exhaustion vulnerability was
    found in the function ReadDDSInfo in coders/dds.c, which
    allowed attackers to cause a denial of service
    (bsc#1074610).

  - CVE-2017-9409: The ReadMPCImage function in mpc.c
    allowed attackers to cause a denial of service (memory
    leak) via a crafted file (bsc#1042948).

  - CVE-2017-1000445: A NULL pointer dereference in the
    MagickCore component might have lead to denial of
    service (bsc#1074425).

  - CVE-2017-17680: Prevent a memory leak in the function
    ReadXPMImage in coders/xpm.c, which allowed attackers to
    cause a denial of service via a crafted XPM image file
    (a different vulnerability than CVE-2017-17882)
    (bsc#1072902).

  - CVE-2017-17882: Prevent a memory leak in the function
    ReadXPMImage in coders/xpm.c, which allowed attackers to
    cause a denial of service via a crafted XPM image file
    (a different vulnerability than CVE-2017-17680)
    (bsc#1074122).

  - CVE-2017-11449: coders/mpc did not enable seekable
    streams and thus could not validate blob sizes, which
    allowed remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via an image received from stdin (bsc#1049373).

  - CVE-2017-12430: A memory exhaustion in the function
    ReadMPCImage in coders/mpc.c allowed attackers to cause
    DoS (bsc#1052252).

  - CVE-2017-12642: Prevent a memory leak vulnerability in
    ReadMPCImage in coders\mpc.c via crafted file allowing
    for DoS (bsc#1052771).

  - CVE-2017-14249: A mishandled EOF check in ReadMPCImage
    in coders/mpc.c that lead to a division by zero in
    GetPixelCacheTileSize in MagickCore/cache.c allowed
    remote attackers to cause a denial of service via a
    crafted file (bsc#1058082).

  - Prevent memory leak via crafted file in pwp.c allowing
    for DoS (bsc#1051412)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074610"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-debuginfo-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-debugsource-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-devel-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-extra-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-extra-debuginfo-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-6_Q16-3-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-devel-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickCore-6_Q16-1-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickWand-6_Q16-1-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-PerlMagick-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-PerlMagick-debuginfo-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-30.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-debuginfo-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-debugsource-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-devel-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-extra-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-extra-debuginfo-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-6_Q16-3-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-devel-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickCore-6_Q16-1-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickWand-6_Q16-1-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-PerlMagick-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-PerlMagick-debuginfo-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-46.1") ) flag++;

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
