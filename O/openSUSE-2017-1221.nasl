#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1221.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104244);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15386", "CVE-2017-15387", "CVE-2017-15388", "CVE-2017-15389", "CVE-2017-15390", "CVE-2017-15391", "CVE-2017-15392", "CVE-2017-15393", "CVE-2017-15394", "CVE-2017-15395", "CVE-2017-15396", "CVE-2017-5124", "CVE-2017-5125", "CVE-2017-5126", "CVE-2017-5127", "CVE-2017-5128", "CVE-2017-5129", "CVE-2017-5130", "CVE-2017-5131", "CVE-2017-5132", "CVE-2017-5133");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2017-1221)");
  script_summary(english:"Check for the openSUSE-2017-1221 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Chromium 62.0.3202.75 fixes the following security
issues :

  - CVE-2017-5124: UXSS with MHTML

  - CVE-2017-5125: Heap overflow in Skia

  - CVE-2017-5126: Use after free in PDFium 

  - CVE-2017-5127: Use after free in PDFium

  - CVE-2017-5128: Heap overflow in WebGL

  - CVE-2017-5129: Use after free in WebAudio 

  - CVE-2017-5132: Incorrect stack manipulation in
    WebAssembly.

  - CVE-2017-5130: Heap overflow in libxml2

  - CVE-2017-5131: Out of bounds write in Skia 

  - CVE-2017-5133: Out of bounds write in Skia 

  - CVE-2017-15386: UI spoofing in Blink

  - CVE-2017-15387: Content security bypass

  - CVE-2017-15388: Out of bounds read in Skia

  - CVE-2017-15389: URL spoofing in OmniBox

  - CVE-2017-15390: URL spoofing in OmniBox 

  - CVE-2017-15391: Extension limitation bypass in
    Extensions.

  - CVE-2017-15392: Incorrect registry key handling in
    PlatformIntegration

  - CVE-2017-15393: Referrer leak in Devtools

  - CVE-2017-15394: URL spoofing in extensions UI

  - CVE-2017-15395: NULL pointer dereference in ImageCapture

  - CVE-2017-15396: Stack overflow in V8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065405"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/30");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-62.0.3202.75-104.32.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-debuginfo-62.0.3202.75-104.32.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-62.0.3202.75-104.32.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debuginfo-62.0.3202.75-104.32.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debugsource-62.0.3202.75-104.32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-62.0.3202.75-118.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-debuginfo-62.0.3202.75-118.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-62.0.3202.75-118.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debuginfo-62.0.3202.75-118.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debugsource-62.0.3202.75-118.1") ) flag++;

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
