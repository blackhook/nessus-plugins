#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kdepim3-6162.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36710);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"openSUSE 10 Security Update : kdepim3 (kdepim3-6162)");
  script_summary(english:"Check for the kdepim3-6162 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates of KMail does not executes links in mail without
confirmation anymore."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdepim3 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim3-kpilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim3-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim3-notes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim3-time-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kitchensync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"kdepim3-3.5.7.enterprise.0.20070904.708012-9.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdepim3-devel-3.5.7.enterprise.0.20070904.708012-9.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdepim3-kpilot-3.5.7.enterprise.0.20070904.708012-9.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdepim3-mobile-3.5.7.enterprise.0.20070904.708012-9.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdepim3-notes-3.5.7.enterprise.0.20070904.708012-9.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdepim3-time-management-3.5.7.enterprise.0.20070904.708012-9.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kitchensync-3.5.7.enterprise.0.20070904.708012-9.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdepim3");
}