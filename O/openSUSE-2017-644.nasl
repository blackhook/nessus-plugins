#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-644.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100611);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-3302", "CVE-2017-3313");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2017-644)");
  script_summary(english:"Check for the openSUSE-2017-644 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mariadb fixes the following issues :

  - update to MariaDB 10.0.30 GA

  - notable changes :

  - XtraDB updated to 5.6.35-80.0

  - TokuDB updated to 5.6.35-80.0

  - PCRE updated to 8.40

  - MDEV-11027: better InnoDB crash recovery progress
    reporting

  - MDEV-11520: improvements to how InnoDB data files are
    extended

  - Improvements to InnoDB startup/shutdown to make it more
    robust

  - MDEV-11233: fix for FULLTEXT index crash

  - MDEV-6143: MariaDB Linux binary tarballs will now always
    untar to directories that match their filename

  - release notes and changelog :

      - https://kb.askmonty.org/en/mariadb-10030-release-notes

      - https://kb.askmonty.org/en/mariadb-10030-changelog

  - fixes the following CVEs: CVE-2017-3313: unspecified
    vulnerability affecting the MyISAM component
    [bsc#1020890] CVE-2017-3302: Use after free in
    libmysqlclient.so [bsc#1022428] 

  - set the default umask to 077 in mysql-systemd-helper
    [bsc#1020976]

  - [bsc#1034911] - tracker bug

  - fixes also [bsc#1020868]

This update for mariadb fixes permissions for /var/run/mysql in
mysql-systemd-helper that were incorrectly set to 700 instead of 755
due to umask. This prevented non-root users from connecting to the
database.

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=996821"
  );
  # https://kb.askmonty.org/en/mariadb-10030-changelog
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10030-changelog/"
  );
  # https://kb.askmonty.org/en/mariadb-10030-release-notes
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10030-release-notes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/05");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient-devel-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient18-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient18-debuginfo-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient_r18-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld-devel-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld18-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld18-debuginfo-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-bench-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-bench-debuginfo-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-client-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-client-debuginfo-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-debuginfo-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-debugsource-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-errormessages-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-test-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-test-debuginfo-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-tools-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-tools-debuginfo-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.30-20.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.30-20.4.1") ) flag++;

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
