#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2420.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(130500);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-13699", "CVE-2019-13700", "CVE-2019-13701", "CVE-2019-13702", "CVE-2019-13703", "CVE-2019-13704", "CVE-2019-13705", "CVE-2019-13706", "CVE-2019-13707", "CVE-2019-13708", "CVE-2019-13709", "CVE-2019-13710", "CVE-2019-13711", "CVE-2019-13713", "CVE-2019-13714", "CVE-2019-13715", "CVE-2019-13716", "CVE-2019-13717", "CVE-2019-13718", "CVE-2019-13719", "CVE-2019-15903");

  script_name(english:"openSUSE Security Update : chromium / re2 (openSUSE-2019-2420)");
  script_summary(english:"Check for the openSUSE-2019-2420 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for chromium, re2 fixes the following issues :

Chromium was updated to 78.0.3904.70 boo#1154806 :

  - CVE-2019-13699: Use-after-free in media

  - CVE-2019-13700: Buffer overrun in Blink

  - CVE-2019-13701: URL spoof in navigation

  - CVE-2019-13702: Privilege elevation in Installer

  - CVE-2019-13703: URL bar spoofing

  - CVE-2019-13704: CSP bypass

  - CVE-2019-13705: Extension permission bypass

  - CVE-2019-13706: Out-of-bounds read in PDFium

  - CVE-2019-13707: File storage disclosure

  - CVE-2019-13708: HTTP authentication spoof

  - CVE-2019-13709: File download protection bypass

  - CVE-2019-13710: File download protection bypass

  - CVE-2019-13711: Cross-context information leak

  - CVE-2019-15903: Buffer overflow in expat

  - CVE-2019-13713: Cross-origin data leak

  - CVE-2019-13714: CSS injection

  - CVE-2019-13715: Address bar spoofing

  - CVE-2019-13716: Service worker state error

  - CVE-2019-13717: Notification obscured

  - CVE-2019-13718: IDN spoof

  - CVE-2019-13719: Notification obscured

  - Various fixes from internal audits, fuzzing and other
    initiatives

  - Use internal resources for icon and appdata"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154806"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium / re2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13706");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libre2-0-20190901-lp151.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libre2-0-debuginfo-20190901-lp151.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"re2-debugsource-20190901-lp151.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"re2-devel-20190901-lp151.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"chromedriver-78.0.3904.70-lp151.2.39.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"chromedriver-debuginfo-78.0.3904.70-lp151.2.39.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"chromium-78.0.3904.70-lp151.2.39.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"chromium-debuginfo-78.0.3904.70-lp151.2.39.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"chromium-debugsource-78.0.3904.70-lp151.2.39.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libre2-0-32bit-20190901-lp151.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libre2-0-32bit-debuginfo-20190901-lp151.10.3.1") ) flag++;

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
