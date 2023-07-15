#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-883.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102217);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7511", "CVE-2017-7515", "CVE-2017-9406", "CVE-2017-9408", "CVE-2017-9775", "CVE-2017-9776");

  script_name(english:"openSUSE Security Update : poppler (openSUSE-2017-883)");
  script_summary(english:"Check for the openSUSE-2017-883 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for poppler fixes the following issues :

Security issues fixed :

  - CVE-2017-9775: DoS stack-based buffer overflow in
    GfxState.cc in pdftocairo via a crafted PDF document
    (bsc#1045719)

  - CVE-2017-9776: DoS integer overflow leading to heap
    buffer overflow in JBIG2Stream.cc via a crafted PDF
    document (bsc#1045721)

  - CVE-2017-7515: Stack exhaustion due to infinite
    recursive call in pdfunite (bsc#1043088)

  - CVE-2017-7511: NULL pointer dereference in pdfunite via
    crafted documents (bsc#1041783)

  - CVE-2017-9406: Memory leak in the gmalloc function in
    gmem.cc (bsc#1042803)

  - CVE-2017-9408: Memory leak in the Object::initArray
    function (bsc#1042802)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045721"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-cpp0-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-cpp0-debuginfo-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-devel-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-glib-devel-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-glib8-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-glib8-debuginfo-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-qt4-4-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-qt4-4-debuginfo-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-qt4-devel-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-qt5-1-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-qt5-1-debuginfo-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler-qt5-devel-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler60-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpoppler60-debuginfo-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"poppler-debugsource-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"poppler-qt-debugsource-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"poppler-qt5-debugsource-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"poppler-tools-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"poppler-tools-debuginfo-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"typelib-1_0-Poppler-0_18-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpoppler-cpp0-32bit-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpoppler-cpp0-debuginfo-32bit-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpoppler-glib8-32bit-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpoppler-glib8-debuginfo-32bit-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpoppler-qt4-4-32bit-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpoppler-qt4-4-debuginfo-32bit-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpoppler-qt5-1-32bit-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpoppler-qt5-1-debuginfo-32bit-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpoppler60-32bit-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpoppler60-debuginfo-32bit-0.43.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-cpp0-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-cpp0-debuginfo-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-devel-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-glib-devel-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-glib8-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-glib8-debuginfo-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt4-4-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt4-4-debuginfo-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt4-devel-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt5-1-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt5-1-debuginfo-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler-qt5-devel-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler60-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpoppler60-debuginfo-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"poppler-debugsource-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"poppler-qt-debugsource-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"poppler-qt5-debugsource-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"poppler-tools-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"poppler-tools-debuginfo-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-Poppler-0_18-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-cpp0-32bit-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-cpp0-debuginfo-32bit-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-glib8-32bit-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-glib8-debuginfo-32bit-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-qt4-4-32bit-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-qt4-4-debuginfo-32bit-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-qt5-1-32bit-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler-qt5-1-debuginfo-32bit-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler60-32bit-0.43.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpoppler60-debuginfo-32bit-0.43.0-5.1") ) flag++;

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
