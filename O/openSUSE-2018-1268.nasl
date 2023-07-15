#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1268.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118444);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12389", "CVE-2018-12390", "CVE-2018-12392", "CVE-2018-12393", "CVE-2018-12395", "CVE-2018-12396", "CVE-2018-12397");

  script_name(english:"openSUSE Security Update : Mozilla Firefox (openSUSE-2018-1268)");
  script_summary(english:"Check for the openSUSE-2018-1268 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Mozilla Firefox to version 60.3.0esr fixes security
issues and stability bugs.

The following security issues were fixed (MFSA 2018-27, boo#1112852) :

  - CVE-2018-12392: Crash with nested event loops

  - CVE-2018-12393: Integer overflow during Unicode
    conversion while loading JavaScript

  - CVE-2018-12395: WebExtension bypass of domain
    restrictions through header rewriting

  - CVE-2018-12396: WebExtension content scripts can execute
    in disallowed contexts

  - CVE-2018-12397: WebExtension local file access
    vulnerability

  - CVE-2018-12389: Memory safety bugs fixed in Firefox ESR
    60.3

  - CVE-2018-12390: Memory safety bugs fixed in Firefox 63
    and Firefox ESR 60.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112852"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-60.3.0-lp150.3.27.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-branding-upstream-60.3.0-lp150.3.27.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-buildsymbols-60.3.0-lp150.3.27.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-debuginfo-60.3.0-lp150.3.27.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-debugsource-60.3.0-lp150.3.27.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-devel-60.3.0-lp150.3.27.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-translations-common-60.3.0-lp150.3.27.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-translations-other-60.3.0-lp150.3.27.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-60.3.0-122.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-branding-upstream-60.3.0-122.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-buildsymbols-60.3.0-122.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debuginfo-60.3.0-122.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debugsource-60.3.0-122.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-devel-60.3.0-122.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-common-60.3.0-122.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-other-60.3.0-122.2") ) flag++;

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
