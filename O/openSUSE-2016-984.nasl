#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-984.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92981);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-9805", "CVE-2014-9807", "CVE-2014-9809", "CVE-2014-9815", "CVE-2014-9817", "CVE-2014-9819", "CVE-2014-9820", "CVE-2014-9831", "CVE-2014-9834", "CVE-2014-9835", "CVE-2014-9837", "CVE-2014-9839", "CVE-2014-9845", "CVE-2014-9846", "CVE-2014-9853", "CVE-2015-8894", "CVE-2015-8896", "CVE-2016-2317", "CVE-2016-2318", "CVE-2016-5240", "CVE-2016-5241", "CVE-2016-5688");

  script_name(english:"openSUSE Security Update : GraphicsMagick (openSUSE-2016-984)");
  script_summary(english:"Check for the openSUSE-2016-984 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for GraphicsMagick fixes the following issues :

  - CVE-2014-9805: SEGV due to a corrupted pnm file
    (boo#983752)

  - CVE-2016-5240: SVG converting issue resulting in DoS
    (endless loop) (boo#983309)

  - CVE-2016-5241: Arithmetic exception (div by 0) in SVG
    conversion (boo#983455)

  - CVE-2014-9846: Overflow in rle file (boo#983521)

  - CVE-2015-8894: Double free in TGA code (boo#983523)

  - CVE-2015-8896: Double free / integer truncation issue
    (boo#983533)

  - CVE-2014-9807: Double free in pdb coder (boo#983794)

  - CVE-2014-9809: SEGV due to corrupted xwd images
    (boo#983799)

  - CVE-2014-9819: Heap overflow in palm files (boo#984142)

  - CVE-2014-9835: Heap overflow in wpf file (boo#984145)

  - CVE-2014-9831: Issues handling of corrupted wpg file
    (boo#984375)

  - CVE-2014-9820: heap overflow in xpm files (boo#984150)

  - CVE-2014-9837: Additional PNM sanity checks (boo#984166)

  - CVE-2014-9815: Crash on corrupted wpg file (boo#984372)

  - CVE-2014-9839: Theoretical out of bound access in via
    color maps (boo#984379)

  - CVE-2014-9845: Crash due to corrupted dib file
    (boo#984394)

  - CVE-2014-9817: Heap buffer overflow in pdb file handling
    (boo#984400)

  - CVE-2014-9853: Memory leak in rle file handling
    (boo#984408)

  - CVE-2014-9834: Heap overflow in pict file (boo#984436)

  - CVE-2016-5688: Various invalid memory reads in
    ImageMagick WPG (boo#985442)

  - CVE-2016-2317: Multiple vulnerabilities when parsing and
    processing SVG files (boo#965853)

  - CVE-2016-2318: Multiple vulnerabilities when parsing and
    processing SVG files (boo#965853)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985442"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GraphicsMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick3-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"GraphicsMagick-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"GraphicsMagick-debuginfo-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"GraphicsMagick-debugsource-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"GraphicsMagick-devel-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libGraphicsMagick++-Q16-11-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libGraphicsMagick++-Q16-11-debuginfo-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libGraphicsMagick++-devel-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libGraphicsMagick-Q16-3-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libGraphicsMagick-Q16-3-debuginfo-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libGraphicsMagick3-config-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libGraphicsMagickWand-Q16-2-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libGraphicsMagickWand-Q16-2-debuginfo-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-GraphicsMagick-1.3.21-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"perl-GraphicsMagick-debuginfo-1.3.21-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / GraphicsMagick-debuginfo / etc");
}
