#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update mozilla-js192-5127.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75959);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : mozilla-js192 (mozilla-js192-5127)");
  script_summary(english:"Check for the mozilla-js192-5127 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla XULRunner to 1.9.2.22

The purpose of this update is to blacklist the compromised DigiNotar
Certificate Authority.

For more information read: MFSA 2011-34
http://www.mozilla.org/security/announce/2011/mfsa2011-34.html"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-34.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-34/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714931"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-js192 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"mozilla-js192-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-js192-debuginfo-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-debuginfo-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-debugsource-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-devel-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-devel-debuginfo-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-gnome-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-gnome-debuginfo-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-translations-common-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-translations-other-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-js192-debuginfo-32bit-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-debuginfo-32bit-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-debuginfo-32bit-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.22-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.22-0.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-xulrunner192");
}
