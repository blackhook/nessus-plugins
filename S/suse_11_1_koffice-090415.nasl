#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update koffice-801.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40252);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"openSUSE Security Update : koffice (koffice-801)");
  script_summary(english:"Check for the koffice-801 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The pdf filter of koffice is prone to several buffer overflows. Due to
the large number of problems and the huge backporting effort that
would be needed the filter has been disabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=487097"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected koffice packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-database-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-database-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-illustration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-planning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-presentation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-spreadsheet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:koffice-wordprocessing");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/15");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"koffice-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-database-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-database-mysql-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-database-psql-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-devel-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-extra-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-illustration-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-planning-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-presentation-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-python-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-ruby-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-spreadsheet-1.6.3-211.12.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"koffice-wordprocessing-1.6.3-211.12.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "koffice / koffice-database / koffice-database-mysql / etc");
}
