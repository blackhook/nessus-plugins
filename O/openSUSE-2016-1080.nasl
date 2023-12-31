#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1080.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93499);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150", "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154", "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-5160", "CVE-2016-5161", "CVE-2016-5162", "CVE-2016-5163", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2016-1080)");
  script_summary(english:"Check for the openSUSE-2016-1080 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 53.0.2785.101 to fix a number of security
issues and bugs.

The following vulnerabilities were fixed: (boo#996648)

  - CVE-2016-5147: Universal XSS in Blink.

  - CVE-2016-5148: Universal XSS in Blink.

  - CVE-2016-5149: Script injection in extensions.

  - CVE-2016-5150: Use after free in Blink.

  - CVE-2016-5151: Use after free in PDFium.

  - CVE-2016-5152: Heap overflow in PDFium.

  - CVE-2016-5153: Use after destruction in Blink.

  - CVE-2016-5154: Heap overflow in PDFium.

  - CVE-2016-5155: Address bar spoofing.

  - CVE-2016-5156: Use after free in event bindings.

  - CVE-2016-5157: Heap overflow in PDFium.

  - CVE-2016-5158: Heap overflow in PDFium.

  - CVE-2016-5159: Heap overflow in PDFium.

  - CVE-2016-5161: Type confusion in Blink.

  - CVE-2016-5162: Extensions web accessible resources
    bypass.

  - CVE-2016-5163: Address bar spoofing.

  - CVE-2016-5164: Universal XSS using DevTools.

  - CVE-2016-5165: Script injection in DevTools.

  - CVE-2016-5166: SMB Relay Attack via Save Page As.

  - CVE-2016-5160: Extensions web accessible resources
    bypass. The following upstream fixes are included :

  - SPDY crasher fixes

  - Disable NV12 DXGI video on AMD

  - Forward --password-store switch to os_crypt

  - Tell the kernel to discard USB requests when they time
    out.

  - disallow WKBackForwardListItem navigations for pushState
    pages

  - arc: bluetooth: Fix advertised uuid

  - fix conflicting PendingIntent for stop button and swipe
    away

A number of tracked build system fixes are included. (boo#996032,
boo#99606, boo#995932)

The following tracked regression fix is included: - Re-enable widevine
plugin (boo#998328)

rpmlint and rpmlint-mini were updated to work around a memory
exhaustion problem with this package on 32 bit (boo#969732)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=996032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=99606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=996648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998328"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpmlint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpmlint-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpmlint-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpmlint-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-53.0.2785.101-120.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-53.0.2785.101-120.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-53.0.2785.101-120.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-53.0.2785.101-120.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-53.0.2785.101-120.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-53.0.2785.101-120.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-53.0.2785.101-120.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-53.0.2785.101-120.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpmlint-1.5-39.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpmlint-mini-1.5-8.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpmlint-mini-debuginfo-1.5-8.7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpmlint-mini-debugsource-1.5-8.7.2") ) flag++;

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
