#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-668.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110679);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2018-668)");
  script_summary(english:"Check for the openSUSE-2018-668 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MariaDB to version 10.0.35 fixes multiple issues:
Security issues fixed :

  - CVE-2018-2782: Unspecified DoS vulnerability in InnoDB
    (bsc#1090518)

  - CVE-2018-2784: Unspecified DoS vulnerability in InnoDB
    (bsc#1090518)

  - CVE-2018-2787: Unspecified vulnerability in InnoDB
    allowing writes (bsc#1090518)

  - CVE-2018-2766: Unspecified DoS vulnerability InnoDB
    (bsc#1090518)

  - CVE-2018-2755: Unspecified vulnerability in Replication
    allowing server compromise (bsc#1090518)

  - CVE-2018-2819: Unspecified DoS vulnerability in InnoDB
    (bsc#1090518)

  - CVE-2018-2817: Unspecified DoS vulnerability in DDL
    (bsc#1090518)

  - CVE-2018-2761: Unspecified DoS vulnerability in Client
    programs (bsc#1090518)

  - CVE-2018-2781: Unspecified DoS vulnerability in
    Server/Optimizer (bsc#1090518)

  - CVE-2018-2771: Unspecified DoS vulnerability in the
    Server/Locking component (bsc#1090518)

  - CVE-2018-2813: Unspecified vulnerability in The DDL
    component allowing unauthorized reads (bsc#1090518)

  - CVE-2018-2767: The embedded server library now supports
    SSL when connecting to remote servers (bsc#1088681)

The following changes are included :

  - XtraDB updated to 5.6.39-83.1

  - TokuDB updated to 5.6.39-83.1

  - InnoDB updated to 5.6.40

  - Fix for Crash in MVCC read after IMPORT TABLESPACE

  - Fix for innodb_read_only trying to modify files if
    transactions were recovered in COMMITTED state

  - Fix for DROP TABLE hang on InnoDB table with FULLTEXT
    index

  - Fix for Crash in INFORMATION_SCHEMA.INNODB_SYS_TABLES
    whenaccessing corrupted record

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090518"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/25");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient-devel-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient18-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient18-debuginfo-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient_r18-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqld-devel-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqld18-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqld18-debuginfo-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-bench-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-bench-debuginfo-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-client-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-client-debuginfo-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-debuginfo-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-debugsource-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-errormessages-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-test-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-test-debuginfo-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-tools-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-tools-debuginfo-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.35-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.35-35.1") ) flag++;

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
