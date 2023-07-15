#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-230.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133759);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/08");

  script_cve_id("CVE-2020-6796", "CVE-2020-6797", "CVE-2020-6798", "CVE-2020-6799", "CVE-2020-6800");
  script_xref(name:"IAVA", value:"2020-A-0072-S");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2020-230)");
  script_summary(english:"Check for the openSUSE-2020-230 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox fixes the following issues :

  - Firefox Extended Support Release 68.5.0 ESR

  - Fixed: Various stability and security fixes

  - Mozilla Firefox ESR68.5 MFSA 2020-06 (bsc#1163368)

  - CVE-2020-6796 (bmo#1610426) Missing bounds check on
    shared memory read in the parent process

  - CVE-2020-6797 (bmo#1596668) Extensions granted
    downloads.open permission could open arbitrary
    applications on Mac OSX

  - CVE-2020-6798 (bmo#1602944) Incorrect parsing of
    template tag could result in JavaScript injection

  - CVE-2020-6799 (bmo#1606596) Arbitrary code execution
    when opening pdf links from other applications, when
    Firefox is configured as default pdf reader

  - CVE-2020-6800 (bmo#1595786, bmo#1596706, bmo#1598543,
    bmo#1604851, bmo#1605777, bmo#1608580, bmo#1608785)
    Memory safety bugs fixed in Firefox 73 and Firefox ESR
    68.5

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163368"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-68.5.0-lp151.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-branding-upstream-68.5.0-lp151.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-buildsymbols-68.5.0-lp151.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-debuginfo-68.5.0-lp151.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-debugsource-68.5.0-lp151.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-devel-68.5.0-lp151.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-translations-common-68.5.0-lp151.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-translations-other-68.5.0-lp151.2.30.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
