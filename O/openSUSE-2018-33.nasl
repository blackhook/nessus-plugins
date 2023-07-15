#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-33.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106062);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-3636", "CVE-2017-3641", "CVE-2017-3653");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2018-33)");
  script_summary(english:"Check for the openSUSE-2018-33 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mariadb fixes several issues.

These security issues were fixed :

  - CVE-2017-3636: Client programs had an unspecified
    vulnerability that could lead to unauthorized access and
    denial of service (bsc#1049399)

  - CVE-2017-3641: DDL unspecified vulnerability could lead
    to denial of service (bsc#1049404)

  - CVE-2017-3653: DML Unspecified vulnerability could lead
    to unauthorized database access (bsc#1049417)

These non-security issues were fixed :

  - Add ODBC support for Connect engine (bsc#1039034)

  - Relax required version for mariadb-errormessages
    (bsc#1072665)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072665"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient-devel-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient18-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient18-debuginfo-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient_r18-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld-devel-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld18-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld18-debuginfo-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-bench-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-bench-debuginfo-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-client-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-client-debuginfo-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-debuginfo-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-debugsource-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-errormessages-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-test-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-test-debuginfo-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-tools-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-tools-debuginfo-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.32-20.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient-devel-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient18-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient18-debuginfo-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient_r18-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqld-devel-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqld18-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqld18-debuginfo-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-bench-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-bench-debuginfo-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-client-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-client-debuginfo-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-debuginfo-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-debugsource-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-errormessages-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-test-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-test-debuginfo-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-tools-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-tools-debuginfo-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.32-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.32-26.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-devel / libmysqlclient18 / libmysqlclient18-32bit / etc");
}
