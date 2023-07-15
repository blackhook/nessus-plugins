#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-103.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106432);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15420", "CVE-2018-6031", "CVE-2018-6032", "CVE-2018-6033", "CVE-2018-6034", "CVE-2018-6035", "CVE-2018-6036", "CVE-2018-6037", "CVE-2018-6038", "CVE-2018-6039", "CVE-2018-6040", "CVE-2018-6041", "CVE-2018-6042", "CVE-2018-6043", "CVE-2018-6045", "CVE-2018-6046", "CVE-2018-6047", "CVE-2018-6048", "CVE-2018-6049", "CVE-2018-6050", "CVE-2018-6051", "CVE-2018-6052", "CVE-2018-6053", "CVE-2018-6054");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2018-103)");
  script_summary(english:"Check for the openSUSE-2018-103 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for chromium to 64.0.3282.119 fixes several issues.

These security issues were fixed :

  - CVE-2018-6031: Use after free in PDFium (boo#1077571)

  - CVE-2018-6032: Same origin bypass in Shared Worker
    (boo#1077571)

  - CVE-2018-6033: Race when opening downloaded files
    (boo#1077571)

  - CVE-2018-6034: Integer overflow in Blink (boo#1077571)

  - CVE-2018-6035: Insufficient isolation of devtools from
    extensions (boo#1077571)

  - CVE-2018-6036: Integer underflow in WebAssembly
    (boo#1077571)

  - CVE-2018-6037: Insufficient user gesture requirements in
    autofill (boo#1077571)

  - CVE-2018-6038: Heap buffer overflow in WebGL
    (boo#1077571)

  - CVE-2018-6039: XSS in DevTools (boo#1077571)

  - CVE-2018-6040: Content security policy bypass
    (boo#1077571)

  - CVE-2018-6041: URL spoof in Navigation (boo#1077571)

  - CVE-2018-6042: URL spoof in OmniBox (boo#1077571)

  - CVE-2018-6043: Insufficient escaping with external URL
    handlers (boo#1077571)

  - CVE-2018-6045: Insufficient isolation of devtools from
    extensions (boo#1077571)

  - CVE-2018-6046: Insufficient isolation of devtools from
    extensions (boo#1077571)

  - CVE-2018-6047: Cross origin URL leak in WebGL
    (boo#1077571)

  - CVE-2018-6048: Referrer policy bypass in Blink
    (boo#1077571)

  - CVE-2017-15420: URL spoofing in Omnibox (boo#1077571)

  - CVE-2018-6049: UI spoof in Permissions (boo#1077571)

  - CVE-2018-6050: URL spoof in OmniBox (boo#1077571)

  - CVE-2018-6051: Referrer leak in XSS Auditor
    (boo#1077571)

  - CVE-2018-6052: Incomplete no-referrer policy
    implementation (boo#1077571)

  - CVE-2018-6053: Leak of page thumbnails in New Tab Page
    (boo#1077571)

  - CVE-2018-6054: Use after free in WebUI (boo#1077571)

Re was updated to version 2018-01-01 (boo#1073323)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077722"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libre2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libre2-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libre2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libre2-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:re2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:re2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libre2-0-20180101-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libre2-0-debuginfo-20180101-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"re2-debugsource-20180101-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"re2-devel-20180101-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"chromedriver-64.0.3282.119-135.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"chromedriver-debuginfo-64.0.3282.119-135.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"chromium-64.0.3282.119-135.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"chromium-debuginfo-64.0.3282.119-135.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"chromium-debugsource-64.0.3282.119-135.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libre2-0-32bit-20180101-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libre2-0-debuginfo-32bit-20180101-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libre2-0 / libre2-0-32bit / libre2-0-debuginfo / etc");
}
