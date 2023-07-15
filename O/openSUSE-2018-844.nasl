#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-844.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111625);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-0739", "CVE-2018-2767", "CVE-2018-3058", "CVE-2018-3062", "CVE-2018-3064", "CVE-2018-3066", "CVE-2018-3070", "CVE-2018-3081");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2018-844)");
  script_summary(english:"Check for the openSUSE-2018-844 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mysql-community-server to version 5.6.41 fixes the
following issues :

Security vulnerabilities fixed :

  - CVE-2018-3064: Fixed an easily exploitable vulnerability
    that allowed a low privileged attacker with network
    access via multiple protocols to compromise the MySQL
    Server. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server as well as unauthorized update, insert or delete
    access to some of MySQL Server accessible data.
    (bsc#1103342)

  - CVE-2018-3070: Fixed an easily exploitable vulnerability
    that allowed a low privileged attacker with network
    access via multiple protocols to compromise MySQL
    Server. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. (bsc#1101679)

  - CVE-2018-0739: Fixed a stack exhaustion in case of
    recursively constructed ASN.1 types. (boo#1087102)

  - CVE-2018-3062: Fixed a difficult to exploit
    vulnerability that allowed low privileged attacker with
    network access via memcached to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server.
    (bsc#1103344)

  - CVE-2018-3081: Fixed a difficult to exploit
    vulnerability that allowed high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Client. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Client as well as unauthorized update, insert or delete
    access to some of MySQL Client accessible data.
    (bsc#1101680)

  - CVE-2018-3058: Fixed an easily exploitable vulnerability
    that allowed low privileged attacker with network access
    via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of
    MySQL Server accessible data. (bsc#1101676)

  - CVE-2018-3066: Fixed a difficult to exploit
    vulnerability allowed high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete
    access to some of MySQL Server accessible data as well
    as unauthorized read access to a subset of MySQL Server
    accessible data. (bsc#1101678)

  - CVE-2018-2767: Fixed a difficult to exploit
    vulnerability that allowed low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized read access to a subset of
    MySQL Server accessible data. (boo#1088681)

You can find more detailed information about this update in the
[release
notes](http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-41.html
)"
  );
  # http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-41.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-41.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103344"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/10");
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

if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client18-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client18-debuginfo-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client_r18-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-bench-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-bench-debuginfo-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-client-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-client-debuginfo-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-debuginfo-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-debugsource-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-errormessages-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-test-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-test-debuginfo-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-tools-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-tools-debuginfo-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.41-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.41-39.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysql56client18-32bit / libmysql56client18 / etc");
}
