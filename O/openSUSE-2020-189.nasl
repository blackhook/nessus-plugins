#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-189.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(133593);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2019-18197", "CVE-2019-19880", "CVE-2019-19923", "CVE-2019-19925", "CVE-2019-19926", "CVE-2020-6381", "CVE-2020-6382", "CVE-2020-6385", "CVE-2020-6387", "CVE-2020-6388", "CVE-2020-6389", "CVE-2020-6390", "CVE-2020-6391", "CVE-2020-6392", "CVE-2020-6393", "CVE-2020-6394", "CVE-2020-6395", "CVE-2020-6396", "CVE-2020-6397", "CVE-2020-6398", "CVE-2020-6399", "CVE-2020-6400", "CVE-2020-6401", "CVE-2020-6402", "CVE-2020-6403", "CVE-2020-6404", "CVE-2020-6405", "CVE-2020-6406", "CVE-2020-6408", "CVE-2020-6409", "CVE-2020-6410", "CVE-2020-6411", "CVE-2020-6412", "CVE-2020-6413", "CVE-2020-6414", "CVE-2020-6415", "CVE-2020-6416", "CVE-2020-6417");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2020-189)");
  script_summary(english:"Check for the openSUSE-2020-189 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for chromium fixes the following issues :

Chromium was updated to version 80.0.3987.87 (boo#1162833).

Security issues fixed :

  - CVE-2020-6381: Integer overflow in JavaScript
    (boo#1162833).

  - CVE-2020-6382: Type Confusion in JavaScript
    (boo#1162833).

  - CVE-2019-18197: Multiple vulnerabilities in XML
    (boo#1162833).

  - CVE-2019-19926: Inappropriate implementation in SQLite
    (boo#1162833).

  - CVE-2020-6385: Insufficient policy enforcement in
    storage (boo#1162833).

  - CVE-2019-19880, CVE-2019-19925: Multiple vulnerabilities
    in SQLite (boo#1162833).

  - CVE-2020-6387: Out of bounds write in WebRTC
    (boo#1162833).

  - CVE-2020-6388: Out of bounds memory access in WebAudio
    (boo#1162833).

  - CVE-2020-6389: Out of bounds write in WebRTC
    (boo#1162833).

  - CVE-2020-6390: Out of bounds memory access in streams
    (boo#1162833).

  - CVE-2020-6391: Insufficient validation of untrusted
    input in Blink (boo#1162833).

  - CVE-2020-6392: Insufficient policy enforcement in
    extensions (boo#1162833).

  - CVE-2020-6393: Insufficient policy enforcement in Blink
    (boo#1162833).

  - CVE-2020-6394: Insufficient policy enforcement in Blink
    (boo#1162833).

  - CVE-2020-6395: Out of bounds read in JavaScript
    (boo#1162833).

  - CVE-2020-6396: Inappropriate implementation in Skia
    (boo#1162833).

  - CVE-2020-6397: Incorrect security UI in sharing
    (boo#1162833).

  - CVE-2020-6398: Uninitialized use in PDFium
    (boo#1162833).

  - CVE-2020-6399: Insufficient policy enforcement in
    AppCache (boo#1162833).

  - CVE-2020-6400: Inappropriate implementation in CORS
    (boo#1162833).

  - CVE-2020-6401: Insufficient validation of untrusted
    input in Omnibox (boo#1162833).

  - CVE-2020-6402: Insufficient policy enforcement in
    downloads (boo#1162833).

  - CVE-2020-6403: Incorrect security UI in Omnibox
    (boo#1162833).

  - CVE-2020-6404: Inappropriate implementation in Blink
    (boo#1162833).

  - CVE-2020-6405: Out of bounds read in SQLite
    (boo#1162833).

  - CVE-2020-6406: Use after free in audio (boo#1162833).

  - CVE-2019-19923: Out of bounds memory access in SQLite
    (boo#1162833).

  - CVE-2020-6408: Insufficient policy enforcement in CORS
    (boo#1162833).

  - CVE-2020-6409: Inappropriate implementation in Omnibox
    (boo#1162833).

  - CVE-2020-6410: Insufficient policy enforcement in
    navigation (boo#1162833).

  - CVE-2020-6411: Insufficient validation of untrusted
    input in Omnibox (boo#1162833).

  - CVE-2020-6412: Insufficient validation of untrusted
    input in Omnibox (boo#1162833).

  - CVE-2020-6413: Inappropriate implementation in Blink
    (boo#1162833).

  - CVE-2020-6414: Insufficient policy enforcement in Safe
    Browsing (boo#1162833).

  - CVE-2020-6415: Inappropriate implementation in
    JavaScript (boo#1162833).

  - CVE-2020-6416: Insufficient data validation in streams
    (boo#1162833).

  - CVE-2020-6417: Inappropriate implementation in installer
    (boo#1162833)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162833"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6416");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-80.0.3987.87-lp151.2.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-debuginfo-80.0.3987.87-lp151.2.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-80.0.3987.87-lp151.2.63.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debuginfo-80.0.3987.87-lp151.2.63.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debugsource-80.0.3987.87-lp151.2.63.1", allowmaj:TRUE) ) flag++;

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
