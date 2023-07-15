#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-674.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123291);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15430", "CVE-2018-16065", "CVE-2018-16066", "CVE-2018-16067", "CVE-2018-16068", "CVE-2018-16069", "CVE-2018-16070", "CVE-2018-16071", "CVE-2018-16073", "CVE-2018-16074", "CVE-2018-16075", "CVE-2018-16076", "CVE-2018-16077", "CVE-2018-16078", "CVE-2018-16079", "CVE-2018-16080", "CVE-2018-16081", "CVE-2018-16082", "CVE-2018-16083", "CVE-2018-16084", "CVE-2018-16085", "CVE-2018-16086", "CVE-2018-16087", "CVE-2018-16088");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2019-674)");
  script_summary(english:"Check for the openSUSE-2019-674 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for Chromium to version 69.0.3497.81 fixes multiple
issues.

Security issues fixed (boo#1107235) :

  - CVE-2018-16065: Out of bounds write in V8

  - CVE-2018-16066:Out of bounds read in Blink

  - CVE-2018-16067: Out of bounds read in WebAudio

  - CVE-2018-16068: Out of bounds write in Mojo

  - CVE-2018-16069:Out of bounds read in SwiftShader

  - CVE-2018-16070: Integer overflow in Skia

  - CVE-2018-16071: Use after free in WebRTC

  - CVE-2018-16073: Site Isolation bypass after tab restore

  - CVE-2018-16074: Site Isolation bypass using Blob URLS

  - Out of bounds read in Little-CMS

  - CVE-2018-16075: Local file access in Blink

  - CVE-2018-16076: Out of bounds read in PDFium

  - CVE-2018-16077: Content security policy bypass in Blink

  - CVE-2018-16078: Credit card information leak in Autofill

  - CVE-2018-16079: URL spoof in permission dialogs

  - CVE-2018-16080: URL spoof in full screen mode

  - CVE-2018-16081: Local file access in DevTools

  - CVE-2018-16082: Stack-based buffer overflow in
    SwiftShader

  - CVE-2018-16083: Out of bounds read in WebRTC

  - CVE-2018-16084: User confirmation bypass in external
    protocol handling

  - CVE-2018-16085: Use after free in Memory Instrumentation

  - CVE-2017-15430: Unsafe navigation in Chromecast
    (boo#1106341)

  - CVE-2018-16086: Script injection in New Tab Page

  - CVE-2018-16087: Multiple download restriction bypass

  - CVE-2018-16088: User gesture requirement bypass The re2
    regular expression library was updated to the current
    version 2018-09-01."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107235"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16085");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libre2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libre2-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libre2-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libre2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:re2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:re2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libre2-0-20180901-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libre2-0-debuginfo-20180901-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"re2-debugsource-20180901-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"re2-devel-20180901-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"chromedriver-69.0.3497.81-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"chromedriver-debuginfo-69.0.3497.81-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"chromium-69.0.3497.81-lp150.2.10.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"chromium-debuginfo-69.0.3497.81-lp150.2.10.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"chromium-debugsource-69.0.3497.81-lp150.2.10.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libre2-0-32bit-20180901-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libre2-0-32bit-debuginfo-20180901-lp150.7.3.1") ) flag++;

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
