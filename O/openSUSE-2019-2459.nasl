#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2459.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130890);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-15903");

  script_name(english:"openSUSE Security Update : MozillaFirefox / MozillaFirefox-branding-SLE (openSUSE-2019-2459)");
  script_summary(english:"Check for the openSUSE-2019-2459 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox, MozillaFirefox-branding-SLE fixes the
following issues :

Changes in MozillaFirefox :

Security issues fixed :

  - CVE-2019-15903: Fixed a heap overflow in the expat
    library (bsc#1149429).

  - CVE-2019-11757: Fixed a use-after-free when creating
    index updates in IndexedDB (bsc#1154738).

  - CVE-2019-11758: Fixed a potentially exploitable crash
    due to 360 Total Security (bsc#1154738).

  - CVE-2019-11759: Fixed a stack-based buffer overflow in
    HKDF output (bsc#1154738).

  - CVE-2019-11760: Fixed a stack-based buffer overflow in
    WebRTC networking (bsc#1154738).

  - CVE-2019-11761: Fixed an unintended access to a
    privileged JSONView object (bsc#1154738).

  - CVE-2019-11762: Fixed a same-origin-property violation
    (bsc#1154738).

  - CVE-2019-11763: Fixed an XSS bypass (bsc#1154738).

  - CVE-2019-11764: Fixed several memory safety bugs
    (bsc#1154738).

Non-security issues fixed :

  - Added Provides-line for translations-common
    (bsc#1153423) .

  - Moved some settings from branding-package here
    (bsc#1153869).

  - Disabled DoH by default.

Changes in MozillaFirefox-branding-SLE :

  - Moved extensions preferences to core package
    (bsc#1153869).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154738"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaFirefox / MozillaFirefox-branding-SLE packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11764");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firefox-esr-branding-openSUSE");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-68.2.0-lp150.3.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-branding-openSUSE-68-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-branding-upstream-68.2.0-lp150.3.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-buildsymbols-68.2.0-lp150.3.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-debuginfo-68.2.0-lp150.3.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-debugsource-68.2.0-lp150.3.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-devel-68.2.0-lp150.3.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-translations-common-68.2.0-lp150.3.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-translations-other-68.2.0-lp150.3.71.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"firefox-esr-branding-openSUSE-68-lp150.3.3.1", allowmaj:TRUE) ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox-branding-openSUSE / firefox-esr-branding-openSUSE / etc");
}
