#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-912.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87488);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-6764", "CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6769", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6774", "CVE-2015-6775", "CVE-2015-6776", "CVE-2015-6777", "CVE-2015-6778", "CVE-2015-6779", "CVE-2015-6780", "CVE-2015-6781", "CVE-2015-6782", "CVE-2015-6783", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786", "CVE-2015-6787", "CVE-2015-6788", "CVE-2015-6789", "CVE-2015-6790", "CVE-2015-6791");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2015-912)");
  script_summary(english:"Check for the openSUSE-2015-912 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 47.0.2526.80 to fix security issues and bugs.

The following vulnerabilities were fixed :

  - CVE-2015-6788: Type confusion in extensions

  - CVE-2015-6789: Use-after-free in Blink

  - CVE-2015-6790: Escaping issue in saved pages

  - CVE-2015-6791: Various fixes from internal audits,
    fuzzing and other initiatives

The following vulnerabilities were fixed in 47.0.2526.73 :

  - CVE-2015-6765: Use-after-free in AppCache

  - CVE-2015-6766: Use-after-free in AppCache

  - CVE-2015-6767: Use-after-free in AppCache

  - CVE-2015-6768: Cross-origin bypass in DOM

  - CVE-2015-6769: Cross-origin bypass in core

  - CVE-2015-6770: Cross-origin bypass in DOM

  - CVE-2015-6771: Out of bounds access in v8

  - CVE-2015-6772: Cross-origin bypass in DOM

  - CVE-2015-6764: Out of bounds access in v8

  - CVE-2015-6773: Out of bounds access in Skia

  - CVE-2015-6774: Use-after-free in Extensions

  - CVE-2015-6775: Type confusion in PDFium

  - CVE-2015-6776: Out of bounds access in PDFium

  - CVE-2015-6777: Use-after-free in DOM

  - CVE-2015-6778: Out of bounds access in PDFium

  - CVE-2015-6779: Scheme bypass in PDFium

  - CVE-2015-6780: Use-after-free in Infobars

  - CVE-2015-6781: Integer overflow in Sfntly

  - CVE-2015-6782: Content spoofing in Omnibox

  - CVE-2015-6783: Signature validation issue in Android
    Crazy Linker.

  - CVE-2015-6784: Escaping issue in saved pages

  - CVE-2015-6785: Wildcard matching issue in CSP

  - CVE-2015-6786: Scheme bypass in CSP

  - CVE-2015-6787: Various fixes from internal audits,
    fuzzing and other initiatives.

  - Multiple vulnerabilities in V8 fixed at the tip of the
    4.7 branch (currently 4.7.80.23)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958481"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-47.0.2526.80-116.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-47.0.2526.80-116.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-47.0.2526.80-116.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-47.0.2526.80-116.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-47.0.2526.80-116.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-47.0.2526.80-116.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-47.0.2526.80-116.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-47.0.2526.80-116.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-47.0.2526.80-116.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-47.0.2526.80-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-47.0.2526.80-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-47.0.2526.80-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-47.0.2526.80-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-47.0.2526.80-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-47.0.2526.80-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-47.0.2526.80-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-47.0.2526.80-61.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-47.0.2526.80-61.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-47.0.2526.80-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-debuginfo-47.0.2526.80-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-47.0.2526.80-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debuginfo-47.0.2526.80-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debugsource-47.0.2526.80-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-gnome-47.0.2526.80-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-kde-47.0.2526.80-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-47.0.2526.80-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-debuginfo-47.0.2526.80-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
