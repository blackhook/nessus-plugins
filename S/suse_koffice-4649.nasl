#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update koffice-4649.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28173);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");

  script_name(english:"openSUSE 10 Security Update : koffice (koffice-4649)");
  script_summary(english:"Check for the koffice-4649 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow in the xpdf code contained in koffice could be
exploited by attackers to potentially execute arbitrary code
(CVE-2007-4352, CVE-2007-5392, CVE-2007-5393)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected koffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"koffice-1.4.2-25.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"koffice-database-1.4.2-25.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"koffice-devel-1.4.2-25.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"koffice-extra-1.4.2-25.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"koffice-illustration-1.4.2-25.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"koffice-presentation-1.4.2-25.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"koffice-spreadsheet-1.4.2-25.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"koffice-wordprocessing-1.4.2-25.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-database-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-database-mysql-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-database-psql-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-devel-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-extra-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-illustration-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-planning-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-presentation-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-python-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-ruby-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-spreadsheet-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"koffice-wordprocessing-1.6.0-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-database-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-database-mysql-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-database-psql-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-devel-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-extra-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-illustration-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-planning-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-presentation-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-python-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-ruby-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-spreadsheet-1.6.3-51.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"koffice-wordprocessing-1.6.3-51.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "koffice / koffice-database / koffice-devel / koffice-extra / etc");
}
