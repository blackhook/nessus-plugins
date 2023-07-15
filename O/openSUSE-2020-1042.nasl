#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1042.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138980);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/27");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2020-1042)");
  script_summary(english:"Check for the openSUSE-2020-1042 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox fixes the following issues :

  - Mozilla Firefox 78.0.2 MFSA 2020-28 (bsc#1173948)

  - MFSA-2020-0003 (bmo#1644076) X-Frame-Options bypass
    using object or embed tags

  - Firefox Extended Support Release 78.0.2esr ESR

  - Fixed: Security fix

  - Fixed: Fixed an accessibility regression in reader mode
    (bmo#1650922)

  - Fixed: Made the address bar more resilient to data
    corruption in the user profile (bmo#1649981)

  - Fixed: Fixed a regression opening certain external
    applications (bmo#1650162)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173948"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-78.0.2-lp151.2.57.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-branding-upstream-78.0.2-lp151.2.57.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-buildsymbols-78.0.2-lp151.2.57.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-debuginfo-78.0.2-lp151.2.57.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-debugsource-78.0.2-lp151.2.57.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-devel-78.0.2-lp151.2.57.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-translations-common-78.0.2-lp151.2.57.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-translations-other-78.0.2-lp151.2.57.1") ) flag++;

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
