#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-270.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108439);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-2562", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2018-270)");
  script_summary(english:"Check for the openSUSE-2018-270 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mariadb fixes the following issues :

MariaDB was updated to 10.0.34 (bsc#1078431)

The following security vulnerabilities are fixed :

  - CVE-2018-2562: Vulnerability in the MySQL Server
    subcomponent: Server : Partition. Easily exploitable
    vulnerability allowed low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server as well as unauthorized update, insert or delete
    access to some of MySQL Server accessible data.

  - CVE-2018-2622: Vulnerability in the MySQL Server
    subcomponent: Server: DDL. Easily exploitable
    vulnerability allowed low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.

  - CVE-2018-2640: Vulnerability in the MySQL Server
    subcomponent: Server: Optimizer. Successful attacks of
    this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server.

  - CVE-2018-2665: Vulnerability in the MySQL Server
    subcomponent: Server: Optimizer. Easily exploitable
    vulnerability allowed low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.

  - CVE-2018-2668: Vulnerability in the MySQL Server
    subcomponent: Server: Optimizer. Easily exploitable
    vulnerability allowed low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.

  - CVE-2018-2612: Vulnerability in the MySQL Server
    subcomponent: InnoDB. Easily exploitable vulnerability
    allowed high privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access
    to critical data or all MySQL Server accessible data and
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server.

The MariaDB external release notes and changelog for this release :

- https://kb.askmonty.org/en/mariadb-10034-release-notes

- https://kb.askmonty.org/en/mariadb-10034-changelog

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078431"
  );
  # https://kb.askmonty.org/en/mariadb-10034-changelog
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10034-changelog/"
  );
  # https://kb.askmonty.org/en/mariadb-10034-release-notes
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10034-release-notes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/19");
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

if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient-devel-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient18-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient18-debuginfo-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqlclient_r18-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqld-devel-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqld18-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysqld18-debuginfo-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-bench-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-bench-debuginfo-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-client-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-client-debuginfo-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-debuginfo-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-debugsource-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-errormessages-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-test-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-test-debuginfo-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-tools-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mariadb-tools-debuginfo-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.34-32.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.34-32.2") ) flag++;

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
