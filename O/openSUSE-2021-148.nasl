#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-148.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145394);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/27");

  script_cve_id("CVE-2020-19667", "CVE-2020-25664", "CVE-2020-25665", "CVE-2020-25666", "CVE-2020-25674", "CVE-2020-25675", "CVE-2020-25676", "CVE-2020-27750", "CVE-2020-27751", "CVE-2020-27752", "CVE-2020-27753", "CVE-2020-27754", "CVE-2020-27755", "CVE-2020-27756", "CVE-2020-27757", "CVE-2020-27758", "CVE-2020-27759", "CVE-2020-27760", "CVE-2020-27761", "CVE-2020-27762", "CVE-2020-27763", "CVE-2020-27764", "CVE-2020-27765", "CVE-2020-27766", "CVE-2020-27767", "CVE-2020-27768", "CVE-2020-27769", "CVE-2020-27770", "CVE-2020-27771", "CVE-2020-27772", "CVE-2020-27773", "CVE-2020-27774", "CVE-2020-27775", "CVE-2020-27776", "CVE-2020-29599");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2021-148)");
  script_summary(english:"Check for the openSUSE-2021-148 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ImageMagick fixes the following issues :

  - CVE-2020-19667: Fixed a stack-based buffer overflow in
    XPM coder could result in a crash (bsc#1179103).

  - CVE-2020-25664: Fixed a heap-based buffer overflow in
    PopShortPixel (bsc#1179202).

  - CVE-2020-25665: Fixed a heap-based buffer overflow in
    WritePALMImage (bsc#1179208).

  - CVE-2020-25666: Fixed an outside the range of
    representable values of type 'int' and signed integer
    overflow (bsc#1179212).

  - CVE-2020-25674: Fixed a heap-based buffer overflow in
    WriteOnePNGImage (bsc#1179223).

  - CVE-2020-25675: Fixed an outside the range of
    representable values of type 'long' and integer overflow
    (bsc#1179240).

  - CVE-2020-25676: Fixed an outside the range of
    representable values of type 'long' and integer overflow
    at MagickCore/pixel.c (bsc#1179244).

  - CVE-2020-27750: Fixed a division by zero in
    MagickCore/colorspace-private.h (bsc#1179260).

  - CVE-2020-27751: Fixed an integer overflow in
    MagickCore/quantum-export.c (bsc#1179269).

  - CVE-2020-27752: Fixed a heap-based buffer overflow in
    PopShortPixel in MagickCore/quantum-private.h
    (bsc#1179346).

  - CVE-2020-27753: Fixed memory leaks in
    AcquireMagickMemory function (bsc#1179397).

  - CVE-2020-27754: Fixed an outside the range of
    representable values of type 'long' and signed integer
    overflow at MagickCore/quantize.c (bsc#1179336).

  - CVE-2020-27755: Fixed memory leaks in ResizeMagickMemory
    function in ImageMagick/MagickCore/memory.c
    (bsc#1179345).

  - CVE-2020-27756: Fixed a division by zero at
    MagickCore/geometry.c (bsc#1179221).

  - CVE-2020-27757: Fixed an outside the range of
    representable values of type 'unsigned long long' at
    MagickCore/quantum-private.h (bsc#1179268).

  - CVE-2020-27758: Fixed an outside the range of
    representable values of type 'unsigned long long'
    (bsc#1179276).

  - CVE-2020-27759: Fixed an outside the range of
    representable values of type 'int' at
    MagickCore/quantize.c (bsc#1179313).

  - CVE-2020-27760: Fixed a division by zero at
    MagickCore/enhance.c (bsc#1179281).

  - CVE-2020-27761: Fixed an outside the range of
    representable values of type 'unsigned long' at
    coders/palm.c (bsc#1179315).

  - CVE-2020-27762: Fixed an outside the range of
    representable values of type 'unsigned char'
    (bsc#1179278).

  - CVE-2020-27763: Fixed a division by zero at
    MagickCore/resize.c (bsc#1179312).

  - CVE-2020-27764: Fixed an outside the range of
    representable values of type 'unsigned long' at
    MagickCore/statistic.c (bsc#1179317).

  - CVE-2020-27765: Fixed a division by zero at
    MagickCore/segment.c (bsc#1179311).

  - CVE-2020-27766: Fixed an outside the range of
    representable values of type 'unsigned long' at
    MagickCore/statistic.c (bsc#1179361).

  - CVE-2020-27767: Fixed an outside the range of
    representable values of type 'float' at
    MagickCore/quantum.h (bsc#1179322).

  - CVE-2020-27768: Fixed an outside the range of
    representable values of type 'unsigned int' at
    MagickCore/quantum-private.h (bsc#1179339).

  - CVE-2020-27769: Fixed an outside the range of
    representable values of type 'float' at
    MagickCore/quantize.c (bsc#1179321).

  - CVE-2020-27770: Fixed an unsigned offset overflowed at
    MagickCore/string.c (bsc#1179343).

  - CVE-2020-27771: Fixed an outside the range of
    representable values of type 'unsigned char' at
    coders/pdf.c (bsc#1179327).

  - CVE-2020-27772: Fixed an outside the range of
    representable values of type 'unsigned int' at
    coders/bmp.c (bsc#1179347).

  - CVE-2020-27773: Fixed a division by zero at
    MagickCore/gem-private.h (bsc#1179285).

  - CVE-2020-27774: Fixed an integer overflow at
    MagickCore/statistic.c (bsc#1179333).

  - CVE-2020-27775: Fixed an outside the range of
    representable values of type 'unsigned char' at
    MagickCore/quantum.h (bsc#1179338).

  - CVE-2020-27776: Fixed an outside the range of
    representable values of type 'unsigned long' at
    MagickCore/statistic.c (bsc#1179362).

  - CVE-2020-29599: Fixed a shell command injection in
    -authenticate (bsc#1179753).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179753"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"ImageMagick-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ImageMagick-config-7-SUSE-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ImageMagick-config-7-upstream-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ImageMagick-debuginfo-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ImageMagick-debugsource-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ImageMagick-devel-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ImageMagick-extra-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ImageMagick-extra-debuginfo-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libMagick++-devel-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"perl-PerlMagick-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"perl-PerlMagick-debuginfo-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ImageMagick-devel-32bit-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-debuginfo-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libMagick++-devel-32bit-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-7.0.7.34-lp151.7.26.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-lp151.7.26.1") ) flag++;

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
