#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-5013.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75654);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-0084", "CVE-2011-2378", "CVE-2011-2980", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2011:0958-1)");
  script_summary(english:"Check for the MozillaFirefox-5013 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 3.6.20.

It fixes bugs and security issues. Following security issues were
fixed: http://www.mozilla.org/security/announce/2011/mfsa2011-30.html
Mozilla Foundation Security Advisory 2011-30 (MFSA 2011-30)

  - Miscellaneous memory safety hazards

    Mozilla developers and community members identified and
    fixed several memory safety bugs in the browser engine
    used in Firefox 3.6 and other Mozilla-based products.
    Some of these bugs showed evidence of memory corruption
    under certain circumstances, and we presume that with
    enough effort at least some of these could be exploited
    to run arbitrary code.

    Gary Kwong, Igor Bukanov, Nils and Bob Clary reported
    memory safety issues which affected Firefox 3.6.
    (CVE-2011-2982)

  - Crash in SVGTextElement.getCharNumAtPosition()

    Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that a SVG text
    manipulation routine contained a dangling pointer
    vulnerability. (CVE-2011-0084)

  - Privilege escalation using event handlers

    Mozilla security researcher moz_bug_r_a_4 reported a
    vulnerability in event management code that would permit
    JavaScript to be run in the wrong context, including
    that of a different website or potentially in a
    chrome-privileged context. (CVE-2011-2981)

  - Dangling pointer vulnerability in appendChild

    Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that appendChild did
    not correctly account for DOM objects it operated upon
    and could be exploited to dereference an invalid
    pointer. (CVE-2011-2378)

  - Privilege escalation dropping a tab element in content
    area

    Mozilla security researcher moz_bug_r_a4 reported that
    web content could receive chrome privileges if it
    registered for drop events and a browser tab element was
    dropped into the content area. (CVE-2011-2984)

  - Binary planting vulnerability in ThinkPadSensor::Startup

    Security researcher Mitja Kolsek of Acros Security
    reported that ThinkPadSensor::Startup could potentially
    be exploited to load a malicious DLL into the running
    process. (CVE-2011-2980) (This issue is likely Windows
    only)

  - Private data leakage using RegExp.input

    Security researcher shutdown reported that data from
    other domains could be read when RegExp.input was set.
    (CVE-2011-2983)"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-30.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-30/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2011-08/msg00040.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-772");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-3.6.20-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-branding-upstream-3.6.20-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-translations-common-3.6.20-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-translations-other-3.6.20-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-js192-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-devel-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-gnome-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-translations-common-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-translations-other-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.20-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.20-1.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
