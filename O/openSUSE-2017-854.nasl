#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-854.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102054);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5091", "CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5094", "CVE-2017-5095", "CVE-2017-5096", "CVE-2017-5097", "CVE-2017-5098", "CVE-2017-5099", "CVE-2017-5100", "CVE-2017-5101", "CVE-2017-5102", "CVE-2017-5103", "CVE-2017-5104", "CVE-2017-5105", "CVE-2017-5106", "CVE-2017-5107", "CVE-2017-5108", "CVE-2017-5109", "CVE-2017-5110", "CVE-2017-7000");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2017-854)");
  script_summary(english:"Check for the openSUSE-2017-854 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update Chromium to version 60.0.3112.78 fixes security issue and
bugs.

The following security issues were fixed :

  - CVE-2017-5091: Use after free in IndexedDB

  - CVE-2017-5092: Use after free in PPAPI

  - CVE-2017-5093: UI spoofing in Blink

  - CVE-2017-5094: Type confusion in extensions

  - CVE-2017-5095: Out-of-bounds write in PDFium

  - CVE-2017-5096: User information leak via Android intents

  - CVE-2017-5097: Out-of-bounds read in Skia

  - CVE-2017-5098: Use after free in V8

  - CVE-2017-5099: Out-of-bounds write in PPAPI

  - CVE-2017-5100: Use after free in Chrome Apps

  - CVE-2017-5101: URL spoofing in OmniBox

  - CVE-2017-5102: Uninitialized use in Skia

  - CVE-2017-5103: Uninitialized use in Skia

  - CVE-2017-5104: UI spoofing in browser

  - CVE-2017-7000: Pointer disclosure in SQLite

  - CVE-2017-5105: URL spoofing in OmniBox

  - CVE-2017-5106: URL spoofing in OmniBox

  - CVE-2017-5107: User information leak via SVG

  - CVE-2017-5108: Type confusion in PDFium

  - CVE-2017-5109: UI spoofing in browser

  - CVE-2017-5110: UI spoofing in payments dialog

  - Various fixes from internal audits, fuzzing and other
    initiatives

A number of upstream bugfixes are also included in this release."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050537"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-60.0.3112.78-104.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-debuginfo-60.0.3112.78-104.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-60.0.3112.78-104.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debuginfo-60.0.3112.78-104.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debugsource-60.0.3112.78-104.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-60.0.3112.78-107.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-debuginfo-60.0.3112.78-107.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-60.0.3112.78-107.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debuginfo-60.0.3112.78-107.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debugsource-60.0.3112.78-107.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
