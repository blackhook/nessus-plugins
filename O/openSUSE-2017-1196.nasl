#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1196.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104234);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10155", "CVE-2017-10227", "CVE-2017-10268", "CVE-2017-10276", "CVE-2017-10279", "CVE-2017-10283", "CVE-2017-10286", "CVE-2017-10294", "CVE-2017-10314", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384", "CVE-2017-3731");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2017-1196)");
  script_summary(english:"Check for the openSUSE-2017-1196 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mysql-community-server to 5.6.38 fixes the following
issues :

Full list of changes :

http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-38.html

CVEs fixed :

  - [boo#1064116] CVE-2017-10379

  - [boo#1064117] CVE-2017-10384

  - [boo#1064115] CVE-2017-10378

  - [boo#1064101] CVE-2017-10268

  - [boo#1064096] CVE-2017-10155

  - [boo#1064118] CVE-2017-3731

  - [boo#1064102] CVE-2017-10276

  - [boo#1064105] CVE-2017-10283

  - [boo#1064112] CVE-2017-10314

  - [boo#1064100] CVE-2017-10227

  - [boo#1064104] CVE-2017-10279

  - [boo#1064108] CVE-2017-10294

  - [boo#1064107] CVE-2017-10286

Additional changes :

  - add 'BuildRequires: unixODBC-devel' to allow ODBC
    support for Connect engine [boo#1039034]

  - update filename in /var/adm/update-messages to match
    documentation, and build-compare pattern

  - some scripts from the tools subpackage, namely:
    wsrep_sst_xtrabackup, wsrep_sst_mariabackup.sh and
    wsrep_sst_xtrabackup-v2.sh need socat

  - fixed incorrect descriptions and mismatching RPM groups"
  );
  # http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-38.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064119"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/30");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client18-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client18-debuginfo-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client_r18-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-bench-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-bench-debuginfo-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-client-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-client-debuginfo-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-debuginfo-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-debugsource-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-errormessages-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-test-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-test-debuginfo-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-tools-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-tools-debuginfo-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.38-24.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client18-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client18-debuginfo-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client_r18-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-bench-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-bench-debuginfo-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-client-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-client-debuginfo-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-debuginfo-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-debugsource-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-errormessages-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-test-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-test-debuginfo-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-tools-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-tools-debuginfo-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.38-30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.38-30.1") ) flag++;

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
