#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-686.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100799);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-6502", "CVE-2017-7606", "CVE-2017-7941", "CVE-2017-7942", "CVE-2017-7943", "CVE-2017-8343", "CVE-2017-8344", "CVE-2017-8345", "CVE-2017-8346", "CVE-2017-8347", "CVE-2017-8348", "CVE-2017-8349", "CVE-2017-8350", "CVE-2017-8351", "CVE-2017-8352", "CVE-2017-8353", "CVE-2017-8354", "CVE-2017-8355", "CVE-2017-8356", "CVE-2017-8357", "CVE-2017-8765", "CVE-2017-8830", "CVE-2017-9098", "CVE-2017-9141", "CVE-2017-9142", "CVE-2017-9143", "CVE-2017-9144");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2017-686)");
  script_summary(english:"Check for the openSUSE-2017-686 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

Security issues fixed :

  - CVE-2017-6502: Possible file-descriptor leak in
    libmagickcore that could be triggered via a specially
    crafted webp file (bsc#1028075).

  - CVE-2017-7943: The ReadSVGImage function in svg.c
    allowed remote attackers to consume an amount of
    available memory via a crafted file (bsc#1034870). Note
    that this only impacts the built-in SVG implementation.
    As we use the librsgv implementation, we are not
    affected.

  - CVE-2017-7942: The ReadAVSImage function in avs.c
    allowed remote attackers to consume an amount of
    available memory via a crafted file (bsc#1034872).

  - CVE-2017-7941: The ReadSGIImage function in sgi.c
    allowed remote attackers to consume an amount of
    available memory via a crafted file (bsc#1034876).

  - CVE-2017-8351: ImageMagick, GraphicsMagick: denial of
    service (memory leak) via a crafted file (ReadPCDImage
    func in pcd.c) (bsc#1036986).

  - CVE-2017-8352: denial of service (memory leak) via a
    crafted file (ReadXWDImage func in xwd.c) (bsc#1036987)

  - CVE-2017-8349: denial of service (memory leak) via a
    crafted file (ReadSFWImage func in sfw.c) (bsc#1036984)

  - CVE-2017-8350: denial of service (memory leak) via a
    crafted file (ReadJNGImage function in png.c)
    (bsc#1036985)

  - CVE-2017-8347: denial of service (memory leak) via a
    crafted file (ReadEXRImage func in exr.c) (bsc#1036982)

  - CVE-2017-8348: denial of service (memory leak) via a
    crafted file (ReadMATImage func in mat.c) (bsc#1036983)

  - CVE-2017-8345: denial of service (memory leak) via a
    crafted file (ReadMNGImage func in png.c) (bsc#1036980)

  - CVE-2017-8346: denial of service (memory leak) via a
    crafted file (ReadDCMImage func in dcm.c) (bsc#1036981)

  - CVE-2017-8353: denial of service (memory leak) via a
    crafted file (ReadPICTImage func in pict.c)
    (bsc#1036988)

  - CVE-2017-8354: denial of service (memory leak) via a
    crafted file (ReadBMPImage func in bmp.c) (bsc#1036989)

  - CVE-2017-8830: denial of service (memory leak) via a
    crafted file (ReadBMPImage func in bmp.c:1379)
    (bsc#1038000)

  - CVE-2017-7606: denial of service (application crash) or
    possibly have unspecified other impact via a crafted
    image (bsc#1033091)

  - CVE-2017-8765: memory leak vulnerability via a crafted
    ICON file (ReadICONImage in coders\icon.c) (bsc#1037527)

  - CVE-2017-8356: denial of service (memory leak) via a
    crafted file (ReadSUNImage function in sun.c)
    (bsc#1036991)

  - CVE-2017-8355: denial of service (memory leak) via a
    crafted file (ReadMTVImage func in mtv.c) (bsc#1036990)

  - CVE-2017-8344: denial of service (memory leak) via a
    crafted file (ReadPCXImage func in pcx.c) (bsc#1036978)

  - CVE-2017-8343: denial of service (memory leak) via a
    crafted file (ReadAAIImage func in aai.c) (bsc#1036977)

  - CVE-2017-8357: denial of service (memory leak) via a
    crafted file (ReadEPTImage func in ept.c) (bsc#1036976)

  - CVE-2017-9098: uninitialized memory usage in the
    ReadRLEImage RLE decoder function coders/rle.c
    (bsc#1040025)

  - CVE-2017-9141: Missing checks in the ReadDDSImage
    function in coders/dds.c could lead to a denial of
    service (assertion) (bsc#1040303)

  - CVE-2017-9142: Missing checks in theReadOneJNGImage
    function in coders/png.c could lead to denial of service
    (assertion) (bsc#1040304)

  - CVE-2017-9143: A possible denial of service attack via
    crafted .art file in ReadARTImage function in
    coders/art.c (bsc#1040306)

  - CVE-2017-9144: A crafted RLE image can trigger a crash
    in coders/rle.c could lead to a denial of service
    (crash) (bsc#1040332)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040332"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/15");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-debuginfo-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-debugsource-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-devel-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-extra-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-extra-debuginfo-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-6_Q16-3-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-devel-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickCore-6_Q16-1-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickWand-6_Q16-1-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-PerlMagick-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-PerlMagick-debuginfo-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-30.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-30.3.1") ) flag++;

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
