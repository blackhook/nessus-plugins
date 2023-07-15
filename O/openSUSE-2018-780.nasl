#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-780.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111432);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-4117", "CVE-2018-6044", "CVE-2018-6153", "CVE-2018-6154", "CVE-2018-6155", "CVE-2018-6156", "CVE-2018-6157", "CVE-2018-6158", "CVE-2018-6159", "CVE-2018-6161", "CVE-2018-6162", "CVE-2018-6163", "CVE-2018-6164", "CVE-2018-6165", "CVE-2018-6166", "CVE-2018-6167", "CVE-2018-6168", "CVE-2018-6169", "CVE-2018-6170", "CVE-2018-6171", "CVE-2018-6172", "CVE-2018-6173", "CVE-2018-6174", "CVE-2018-6175", "CVE-2018-6176", "CVE-2018-6177", "CVE-2018-6178", "CVE-2018-6179");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2018-780)");
  script_summary(english:"Check for the openSUSE-2018-780 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Chromium to version 68.0.3440.75 fixes multiple
issues.

Security issues fixed (boo#1102530) :

  - CVE-2018-6153: Stack-based buffer overflow in Skia

  - CVE-2018-6154: Heap buffer overflow in WebGL

  - CVE-2018-6155: Use after free in WebRTC

  - CVE-2018-6156: Heap buffer overflow in WebRTC

  - CVE-2018-6157: Type confusion in WebRTC

  - CVE-2018-6158: Use after free in Blink

  - CVE-2018-6159: Same origin policy bypass in
    ServiceWorker

  - CVE-2018-6161: Same origin policy bypass in WebAudio

  - CVE-2018-6162: Heap buffer overflow in WebGL

  - CVE-2018-6163: URL spoof in Omnibox

  - CVE-2018-6164: Same origin policy bypass in
    ServiceWorker

  - CVE-2018-6165: URL spoof in Omnibox

  - CVE-2018-6166: URL spoof in Omnibox

  - CVE-2018-6167: URL spoof in Omnibox

  - CVE-2018-6168: CORS bypass in Blink

  - CVE-2018-6169: Permissions bypass in extension
    installation

  - CVE-2018-6170: Type confusion in PDFium

  - CVE-2018-6171: Use after free in WebBluetooth

  - CVE-2018-6172: URL spoof in Omnibox

  - CVE-2018-6173: URL spoof in Omnibox

  - CVE-2018-6174: Integer overflow in SwiftShader

  - CVE-2018-6175: URL spoof in Omnibox

  - CVE-2018-6176: Local user privilege escalation in
    Extensions

  - CVE-2018-6177: Cross origin information leak in Blink

  - CVE-2018-6178: UI spoof in Extensions

  - CVE-2018-6179: Local file information leak in Extensions

  - CVE-2018-6044: Request privilege escalation in
    Extensions

  - CVE-2018-4117: Cross origin information leak in Blink

The following user interface changes are included :

  - Chrome will show the 'Not secure' warning on all plain
    HTTP pages"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102530"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/30");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-68.0.3440.75-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-debuginfo-68.0.3440.75-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-68.0.3440.75-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debuginfo-68.0.3440.75-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debugsource-68.0.3440.75-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-68.0.3440.75-164.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-debuginfo-68.0.3440.75-164.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-68.0.3440.75-164.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debuginfo-68.0.3440.75-164.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debugsource-68.0.3440.75-164.1") ) flag++;

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
