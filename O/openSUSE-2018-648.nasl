#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-648.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110592);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000456", "CVE-2017-14517", "CVE-2017-14518", "CVE-2017-14520", "CVE-2017-14617", "CVE-2017-14928", "CVE-2017-14975", "CVE-2017-14976", "CVE-2017-14977", "CVE-2017-15565", "CVE-2017-9865");

  script_name(english:"openSUSE Security Update : poppler (openSUSE-2018-648)");
  script_summary(english:"Check for the openSUSE-2018-648 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for poppler fixes the following issues :

These security issues were fixed :

  - CVE-2017-14517: Prevent NULL pointer dereference in the
    XRef::parseEntry() function via a crafted PDF document
    (bsc#1059066).

  - CVE-2017-9865: Fixed a stack-based buffer overflow
    vulnerability in GfxState.cc that would have allowed
    attackers to facilitate a denial-of-service attack via
    specially crafted PDF documents. (bsc#1045939)

  - CVE-2017-14518: Remedy a floating point exception in
    isImageInterpolationRequired() that could have been
    exploited using a specially crafted PDF document.
    (bsc#1059101)

  - CVE-2017-14520: Remedy a floating point exception in
    Splash::scaleImageYuXd() that could have been exploited
    using a specially crafted PDF document. (bsc#1059155)

  - CVE-2017-14617: Fixed a floating point exception in
    Stream.cc, which may lead to a potential attack when
    handling malicious PDF files. (bsc#1060220)

  - CVE-2017-14928: Fixed a NULL pointer dereference in
    AnnotRichMedia::Configuration::Configuration() in
    Annot.cc, which may lead to a potential attack when
    handling malicious PDF files. (bsc#1061092)

  - CVE-2017-14975: Fixed a NULL pointer dereference
    vulnerability, that existed because a data structure in
    FoFiType1C.cc was not initialized, which allowed an
    attacker to launch a denial of service attack.
    (bsc#1061263)

  - CVE-2017-14976: Fixed a heap-based buffer over-read
    vulnerability in FoFiType1C.cc that occurred when an
    out-of-bounds font dictionary index was encountered,
    which allowed an attacker to launch a denial of service
    attack. (bsc#1061264)

  - CVE-2017-14977: Fixed a NULL pointer dereference
    vulnerability in the FoFiTrueType::getCFFBlock()
    function in FoFiTrueType.cc that occurred due to lack of
    validation of a table pointer, which allows an attacker
    to launch a denial of service attack. (bsc#1061265)

  - CVE-2017-15565: Prevent NULL pointer dereference in the
    GfxImageColorMap::getGrayLine() function via a crafted
    PDF document (bsc#1064593).

  - CVE-2017-1000456: Validate boundaries in
    TextPool::addWord to prevent overflows in subsequent
    calculations (bsc#1074453).

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074453"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-cpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-cpp0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-cpp0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-cpp0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib8-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt5-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt5-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt5-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt5-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler60-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler60-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler60-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-qt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-qt5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Poppler-0_18");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-cpp0-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-cpp0-debuginfo-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-devel-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-glib-devel-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-glib8-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-glib8-debuginfo-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt4-4-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt4-4-debuginfo-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt4-devel-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt5-1-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt5-1-debuginfo-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt5-devel-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler60-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler60-debuginfo-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"poppler-debugsource-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"poppler-qt-debugsource-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"poppler-qt5-debugsource-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"poppler-tools-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"poppler-tools-debuginfo-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-Poppler-0_18-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-cpp0-32bit-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-cpp0-debuginfo-32bit-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-glib8-32bit-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-glib8-debuginfo-32bit-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-qt4-4-32bit-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-qt4-4-debuginfo-32bit-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-qt5-1-32bit-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-qt5-1-debuginfo-32bit-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler60-32bit-0.43.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler60-debuginfo-32bit-0.43.0-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpoppler-qt4-4 / libpoppler-qt4-4-32bit / etc");
}
