#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update bytefx-data-mysql-5558.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34070);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-3422");

  script_name(english:"openSUSE 10 Security Update : bytefx-data-mysql (bytefx-data-mysql-5558)");
  script_summary(english:"Check for the bytefx-data-mysql-5558 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This patch fixes two security problems and one critical bug :

Makes sure that values of all the tags which can be exploited are
encoded to make sure no exploit is possible. (CVE-2008-3422)

A header injection problem in Sys.Web was fixed."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bytefx-data-mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bytefx-data-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibm-data-db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-core-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-jscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-locale-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-nunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/03");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"bytefx-data-mysql-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ibm-data-db2-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-core-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-data-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-data-firebird-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-data-oracle-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-data-postgresql-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-data-sqlite-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-data-sybase-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-devel-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-extras-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-jscript-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-locale-extras-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-nunit-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-web-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mono-winforms-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"mono-core-32bit-1.1.18.1-12.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"bytefx-data-mysql-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"ibm-data-db2-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-complete-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-core-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-data-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-data-firebird-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-data-oracle-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-data-postgresql-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-data-sqlite-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-data-sybase-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-devel-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-extras-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-jscript-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-locale-extras-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-nunit-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-web-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mono-winforms-1.2.5-16.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"mono-core-32bit-1.2.5-16.5") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mono-core");
}
