#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1279.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104648);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7826", "CVE-2017-7828", "CVE-2017-7830");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2017-1279)");
  script_summary(english:"Check for the openSUSE-2017-1279 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to 52.5.0esr (boo#1068101)

MFSA 2017-25

  - CVE-2017-7828: Fixed a use-after-free of PressShell
    while restyling layout

  - CVE-2017-7830: Cross-origin URL information leak through
    Resource Timing API

  - CVE-2017-7826: Memory safety bugs fixed in Firefox 57
    and Firefox ESR 52.5

Also fixed :

  - Correct plugin directory for aarch64 (boo#1061207). The
    wrapper script was not detecting aarch64 as a 64 bit
    architecture, thus used /usr/lib/browser-plugins/."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068101"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/17");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-52.5.0-57.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-branding-upstream-52.5.0-57.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-buildsymbols-52.5.0-57.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debuginfo-52.5.0-57.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debugsource-52.5.0-57.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-devel-52.5.0-57.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-common-52.5.0-57.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-other-52.5.0-57.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-52.5.0-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-branding-upstream-52.5.0-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-buildsymbols-52.5.0-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debuginfo-52.5.0-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debugsource-52.5.0-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-devel-52.5.0-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-common-52.5.0-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-other-52.5.0-66.1") ) flag++;

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
