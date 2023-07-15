#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1391.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140509);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/15");

  script_cve_id("CVE-2020-15663", "CVE-2020-15664", "CVE-2020-15670");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2020-1391)");
  script_summary(english:"Check for the openSUSE-2020-1391 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox fixes the following issues :

  - Firefox Extended Support Release 78.2.0 ESR

  - Fixed: Various stability, functionality, and security
    fixes

  - Mozilla Firefox ESR 78.2 MFSA 2020-38 (bsc#1175686)

  - CVE-2020-15663 (bmo#1643199) Downgrade attack on the
    Mozilla Maintenance Service could have resulted in
    escalation of privilege

  - CVE-2020-15664 (bmo#1658214) Attacker-induced prompt for
    extension installation

  - CVE-2020-15670 (bmo#1651001, bmo#1651449, bmo#1653626,
    bmo#1656957) Memory safety bugs fixed in Firefox 80 and
    Firefox ESR 78.2

  - Fixed Firefox tab crash in FIPS mode (bsc#1174284).

  - Fix broken translation-loading (bsc#1173991) 

  - allow addon sideloading

  - mark signatures for langpacks non-mandatory

  - do not autodisable user profile scopes

  - Google API key is not usable for geolocation service any
    more

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175686"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15663");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-78.2.0-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-branding-upstream-78.2.0-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-buildsymbols-78.2.0-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-debuginfo-78.2.0-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-debugsource-78.2.0-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-devel-78.2.0-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-translations-common-78.2.0-lp152.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-translations-other-78.2.0-lp152.2.18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
