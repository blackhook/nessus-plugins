#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1154.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93854);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-6662");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2016-1154)");
  script_summary(english:"Check for the openSUSE-2016-1154 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mariadb to 10.0.27 fixes the following issues :

Security issue fixed :

  - CVE-2016-6662: A malicious user with SQL and filesystem
    access could create a my.cnf in the datadir and, under
    certain circumstances, execute arbitrary code as mysql
    (or even root) user. (bsc#998309)

  - release notes :

  - https://kb.askmonty.org/en/mariadb-10027-release-notes

  - changelog :

  - https://kb.askmonty.org/en/mariadb-10027-changelog

Bugs fixed :

  - Make ORDER BY optimization functions take into account
    multiple equalities. (bsc#949520)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998309"
  );
  # https://kb.askmonty.org/en/mariadb-10027-changelog
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10027-changelog/"
  );
  # https://kb.askmonty.org/en/mariadb-10027-release-notes
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10027-release-notes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient-devel-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient18-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient18-debuginfo-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient_r18-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqld-devel-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqld18-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqld18-debuginfo-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-bench-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-bench-debuginfo-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-client-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-client-debuginfo-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-debuginfo-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-debugsource-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-errormessages-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-test-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-test-debuginfo-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-tools-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-tools-debuginfo-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.27-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.27-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-devel / libmysqlclient18 / libmysqlclient18-32bit / etc");
}
