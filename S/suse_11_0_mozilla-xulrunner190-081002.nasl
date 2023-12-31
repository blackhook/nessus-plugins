#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update mozilla-xulrunner190-234.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40074);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068");

  script_name(english:"openSUSE Security Update : mozilla-xulrunner190 (mozilla-xulrunner190-234)");
  script_summary(english:"Check for the mozilla-xulrunner190-234 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings the mozilla-xulrunner190 engine to version 1.9.0.3,
fixing a number of bugs and security problems :

MFSA 2008-44 / CVE-2008-4067 / CVE-2008-4068: resource: traversal
vulnerabilities

MFSA 2008-43: BOM characters stripped from JavaScript before execution
CVE-2008-4065: Stripped BOM characters bug CVE-2008-4066: HTML escaped
low surrogates bug

MFSA 2008-42 Crashes with evidence of memory corruption
(rv:1.9.0.2/1.8.1.17): CVE-2008-4061: Jesse Ruderman reported a crash
in the layout engine. CVE-2008-4062: Igor Bukanov, Philip Taylor,
Georgi Guninski, and Antoine Labour reported crashes in the JavaScript
engine. CVE-2008-4063: Jesse Ruderman, Bob Clary, and Martijn Wargers
reported crashes in the layout engine which only affected Firefox 3.
CVE-2008-4064: David Maciejak and Drew Yao reported crashes in
graphics rendering which only affected Firefox 3.

MFSA 2008-41 Privilege escalation via XPCnativeWrapper pollution
CVE-2008-4058: XPCnativeWrapper pollution bugs CVE-2008-4059:
XPCnativeWrapper pollution (Firefox 2) CVE-2008-4060: Documents
without script handling objects

MFSA 2008-40 / CVE-2008-3837: Forced mouse drag"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=429179"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-xulrunner190 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(22, 79, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-1.9.0.3-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-devel-1.9.0.3-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.3-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-translations-1.9.0.3-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.3-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.3-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.3-1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-xulrunner190");
}
