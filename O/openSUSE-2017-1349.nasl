#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1349.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105235);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15408", "CVE-2017-15409", "CVE-2017-15410", "CVE-2017-15411", "CVE-2017-15412", "CVE-2017-15413", "CVE-2017-15415", "CVE-2017-15416", "CVE-2017-15417", "CVE-2017-15418", "CVE-2017-15419", "CVE-2017-15420", "CVE-2017-15422", "CVE-2017-15423", "CVE-2017-15424", "CVE-2017-15425", "CVE-2017-15426", "CVE-2017-15427");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2017-1349)");
  script_summary(english:"Check for the openSUSE-2017-1349 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Chromium 63.0.3239.84 fixes the following security
issues :

  - CVE-2017-15408: Heap buffer overflow in PDFium

  - CVE-2017-15409: Out of bounds write in Skia

  - CVE-2017-15410: Use after free in PDFium

  - CVE-2017-15411: Use after free in PDFium

  - CVE-2017-15412: Use after free in libXML

  - CVE-2017-15413: Type confusion in WebAssembly

  - CVE-2017-15415: Pointer information disclosure in IPC
    call

  - CVE-2017-15416: Out of bounds read in Blink

  - CVE-2017-15417: Cross origin information disclosure in
    Skia

  - CVE-2017-15418: Use of uninitialized value in Skia

  - CVE-2017-15419: Cross origin leak of redirect URL in
    Blink

  - CVE-2017-15420: URL spoofing in Omnibox

  - CVE-2017-15422: Integer overflow in ICU

  - CVE-2017-15423: Issue with SPAKE implementation in
    BoringSSL

  - CVE-2017-15424: URL Spoof in Omnibox

  - CVE-2017-15425: URL Spoof in Omnibox

  - CVE-2017-15426: URL Spoof in Omnibox

  - CVE-2017-15427: Insufficient blocking of JavaScript in
    Omnibox"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071691"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
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

if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-63.0.3239.84-104.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-debuginfo-63.0.3239.84-104.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-63.0.3239.84-104.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debuginfo-63.0.3239.84-104.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debugsource-63.0.3239.84-104.41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-63.0.3239.84-127.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-debuginfo-63.0.3239.84-127.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-63.0.3239.84-127.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debuginfo-63.0.3239.84-127.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debugsource-63.0.3239.84-127.1") ) flag++;

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
