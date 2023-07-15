#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-825.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150269);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-21212",
    "CVE-2021-30521",
    "CVE-2021-30522",
    "CVE-2021-30523",
    "CVE-2021-30524",
    "CVE-2021-30525",
    "CVE-2021-30526",
    "CVE-2021-30527",
    "CVE-2021-30528",
    "CVE-2021-30529",
    "CVE-2021-30530",
    "CVE-2021-30531",
    "CVE-2021-30532",
    "CVE-2021-30533",
    "CVE-2021-30534",
    "CVE-2021-30535",
    "CVE-2021-30536",
    "CVE-2021-30537",
    "CVE-2021-30538",
    "CVE-2021-30539",
    "CVE-2021-30540"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2021-825)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for chromium fixes the following issues :

Chromium 91.0.4472.77 (boo#1186458) :

  - Support Managed configuration API for Web Applications

  - WebOTP API: cross-origin iframe support

  - CSS custom counter styles

  - Support JSON Modules

  - Clipboard: read-only files support

  - Remove webkitBeforeTextInserted &
    webkitEditableCOntentChanged JS events

  - Honor media HTML attribute for link icon

  - Import Assertions

  - Class static initializer blocks

  - Ergonomic brand checks for private fields

  - Expose WebAssembly SIMD

  - New Feature: WebTransport

  - ES Modules for service workers ('module' type option)

  - Suggested file name and location for the File System
    Access API

  - adaptivePTime property for RTCRtpEncodingParameters

  - Block HTTP port 10080 - mitigation for NAT Slipstream
    2.0 attack

  - Support WebSockets over HTTP/2

  - Support 103 Early Hints for Navigation

  - CVE-2021-30521: Heap buffer overflow in Autofill

  - CVE-2021-30522: Use after free in WebAudio

  - CVE-2021-30523: Use after free in WebRTC

  - CVE-2021-30524: Use after free in TabStrip

  - CVE-2021-30525: Use after free in TabGroups

  - CVE-2021-30526: Out of bounds write in TabStrip

  - CVE-2021-30527: Use after free in WebUI

  - CVE-2021-30528: Use after free in WebAuthentication

  - CVE-2021-30529: Use after free in Bookmarks

  - CVE-2021-30530: Out of bounds memory access in WebAudio

  - CVE-2021-30531: Insufficient policy enforcement in
    Content Security Policy

  - CVE-2021-30532: Insufficient policy enforcement in
    Content Security Policy

  - CVE-2021-30533: Insufficient policy enforcement in
    PopupBlocker

  - CVE-2021-30534: Insufficient policy enforcement in
    iFrameSandbox

  - CVE-2021-30535: Double free in ICU

  - CVE-2021-21212: Insufficient data validation in
    networking

  - CVE-2021-30536: Out of bounds read in V8

  - CVE-2021-30537: Insufficient policy enforcement in
    cookies

  - CVE-2021-30538: Insufficient policy enforcement in
    content security policy

  - CVE-2021-30539: Insufficient policy enforcement in
    content security policy

  - CVE-2021-30540: Incorrect security UI in payments

  - Various fixes from internal audits, fuzzing and other
    initiatives");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186458");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30535");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-91.0.4472.77-lp152.2.98.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-debuginfo-91.0.4472.77-lp152.2.98.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-91.0.4472.77-lp152.2.98.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-debuginfo-91.0.4472.77-lp152.2.98.1", allowmaj:TRUE) ) flag++;

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
