#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update postgresql-4958.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(30198);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600");

  script_name(english:"openSUSE 10 Security Update : postgresql (postgresql-4958)");
  script_summary(english:"Check for the postgresql-4958 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version update to 8.1.11 fixes among other things several
security issues :

  - Index Functions Privilege Escalation: CVE-2007-6600

  - Regular Expression Denial-of-Service: CVE-2007-4772,
    CVE-2007-6067, CVE-2007-4769

  - DBLink Privilege Escalation: CVE-2007-6601"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_cwe_id(189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"postgresql-8.1.11-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"postgresql-contrib-8.1.11-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"postgresql-devel-8.1.11-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"postgresql-libs-8.1.11-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"postgresql-pl-8.1.11-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"postgresql-server-8.1.11-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"postgresql-libs-32bit-8.1.11-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"postgresql-8.1.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"postgresql-contrib-8.1.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"postgresql-devel-8.1.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"postgresql-libs-8.1.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"postgresql-pl-8.1.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"postgresql-server-8.1.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"postgresql-libs-32bit-8.1.11-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
