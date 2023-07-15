#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1366.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105246);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7843");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2017-1366)");
  script_summary(english:"Check for the openSUSE-2017-1366 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox to 52.5.2esr fixes the following 
issue :

  - CVE-2017-7843: Web worker in Private Browsing mode can
    write IndexedDB data (boo#1072034, bmo#1410106, MFSA
    2017-28)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072034"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-52.5.2-57.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-branding-upstream-52.5.2-57.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-buildsymbols-52.5.2-57.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debuginfo-52.5.2-57.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debugsource-52.5.2-57.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-devel-52.5.2-57.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-common-52.5.2-57.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-other-52.5.2-57.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-52.5.2-69.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-branding-upstream-52.5.2-69.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-buildsymbols-52.5.2-69.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debuginfo-52.5.2-69.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debugsource-52.5.2-69.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-devel-52.5.2-69.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-common-52.5.2-69.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-other-52.5.2-69.1") ) flag++;

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
