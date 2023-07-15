#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-546.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110275);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-6123", "CVE-2018-6124", "CVE-2018-6125", "CVE-2018-6126", "CVE-2018-6127", "CVE-2018-6128", "CVE-2018-6129", "CVE-2018-6130", "CVE-2018-6131", "CVE-2018-6132", "CVE-2018-6133", "CVE-2018-6134", "CVE-2018-6135", "CVE-2018-6136", "CVE-2018-6137", "CVE-2018-6138", "CVE-2018-6139", "CVE-2018-6140", "CVE-2018-6141", "CVE-2018-6142", "CVE-2018-6143", "CVE-2018-6144", "CVE-2018-6145", "CVE-2018-6147");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2018-546)");
  script_summary(english:"Check for the openSUSE-2018-546 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for chromium to version 66.0.3359.181 fixes the following
issues :

The following security issues were fixed (boo#1095163) :

  - CVE-2018-6123: Use after free in Blink.

  - CVE-2018-6124: Type confusion in Blink.

  - CVE-2018-6125: Overly permissive policy in WebUSB.

  - CVE-2018-6126: Heap buffer overflow in Skia.

  - CVE-2018-6127: Use after free in indexedDB.

  - CVE-2018-6128: uXSS in Chrome on iOS.

  - CVE-2018-6129: Out of bounds memory access in WebRTC.

  - CVE-2018-6130: Out of bounds memory access in WebRTC.

  - CVE-2018-6131: Incorrect mutability protection in
    WebAssembly.

  - CVE-2018-6132: Use of uninitialized memory in WebRTC.

  - CVE-2018-6133: URL spoof in Omnibox.

  - CVE-2018-6134: Referrer Policy bypass in Blink.

  - CVE-2018-6135: UI spoofing in Blink.

  - CVE-2018-6136: Out of bounds memory access in V8.

  - CVE-2018-6137: Leak of visited status of page in Blink.

  - CVE-2018-6138: Overly permissive policy in Extensions.

  - CVE-2018-6139: Restrictions bypass in the debugger
    extension API.

  - CVE-2018-6140: Restrictions bypass in the debugger
    extension API.

  - CVE-2018-6141: Heap buffer overflow in Skia.

  - CVE-2018-6142: Out of bounds memory access in V8.

  - CVE-2018-6143: Out of bounds memory access in V8.

  - CVE-2018-6144: Out of bounds memory access in PDFium.

  - CVE-2018-6145: Incorrect escaping of MathML in Blink.

  - CVE-2018-6147: Password fields not taking advantage of
    OS protections in Views.

Additional changes :

  - Autoplay: Force enable on desktop for Web Audio This
    update enables the 'Strict site isolation' feature for a
    larger percentage of users. This feature is a mitigation
    against the Spectre vulnerabilities. It can be turned on
    via: chrome://flags/#enable-site-per-process It can be
    disabled via:
    chrome://flags/#site-isolation-trial-opt-out"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095163"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/01");
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

if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-67.0.3396.62-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-debuginfo-67.0.3396.62-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-67.0.3396.62-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debuginfo-67.0.3396.62-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debugsource-67.0.3396.62-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-67.0.3396.62-161.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-debuginfo-67.0.3396.62-161.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-67.0.3396.62-161.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debuginfo-67.0.3396.62-161.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debugsource-67.0.3396.62-161.1") ) flag++;

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
