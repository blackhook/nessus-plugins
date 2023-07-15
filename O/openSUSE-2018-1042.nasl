#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1042.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117690);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12383", "CVE-2018-12385");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2018-1042)");
  script_summary(english:"Check for the openSUSE-2018-1042 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Mozilla Firefox to version 60.2.1esr fixes the
following issues :

Security issues fixed (MFSA 2018-23) :

  - CVE-2018-12385: Crash in TransportSecurityInfo due to
    cached data (boo#1109363)

  - CVE-2018-12383: Setting a master password did not delete
    unencrypted previously stored passwords (boo#1107343)

Bugx fixed :

  - Fixed a startup crash affecting users migrating from
    older ESR releases"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109363"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/25");
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

if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-60.2.1-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-branding-upstream-60.2.1-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-buildsymbols-60.2.1-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-debuginfo-60.2.1-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-debugsource-60.2.1-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-devel-60.2.1-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-translations-common-60.2.1-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-translations-other-60.2.1-lp150.3.17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-60.2.1-112.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-branding-upstream-60.2.1-112.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-buildsymbols-60.2.1-112.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debuginfo-60.2.1-112.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debugsource-60.2.1-112.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-devel-60.2.1-112.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-common-60.2.1-112.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-other-60.2.1-112.1") ) flag++;

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
