#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-866.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102056);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-3633", "CVE-2017-3634", "CVE-2017-3635", "CVE-2017-3636", "CVE-2017-3641", "CVE-2017-3647", "CVE-2017-3648", "CVE-2017-3649", "CVE-2017-3651", "CVE-2017-3652", "CVE-2017-3653", "CVE-2017-3732");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2017-866)");
  script_summary(english:"Check for the openSUSE-2017-866 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mysql-community-server to version 5.6.37 fixes
security issues and bugs.

The following vulnerabilities were fixed :

  - CVE-2017-3633: Memcached unspecified vulnerability
    (boo#1049394) 

  - CVE-2017-3634: DML unspecified vulnerability
    (boo#1049396) 

  - CVE-2017-3635: C API unspecified vulnerability
    (boo#1049398) 

  - CVE-2017-3636: Client programs unspecified vulnerability
    (boo#1049399) 

  - CVE-2017-3641: DML unspecified vulnerability
    (boo#1049404) 

  - CVE-2017-3647: Replication unspecified vulnerability
    (boo#1049410) 

  - CVE-2017-3648: Charsets unspecified vulnerability
    (boo#1049411) 

  - CVE-2017-3649: Replication unspecified vulnerability
    (boo#1049412) 

  - CVE-2017-3651: Client mysqldump unspecified
    vulnerability (boo#1049415) 

  - CVE-2017-3652: DDL unspecified vulnerability
    (boo#1049416) 

  - CVE-2017-3653: DDL unspecified vulnerability
    (boo#1049417) 

  - CVE-2017-3732: Security, Encryption unspecified
    vulnerability (boo#1049421) The following general
    changes are included :

  - switch systemd unit file from 'Restart=on-failure' to
    'Restart=on-abort'

  - update file lists for new man-pages and tools (for
    mariadb) 

For a list of upstream changes in this release, see:
http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-37.html"
  );
  # http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-37.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049398"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049422"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");
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

if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client18-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client18-debuginfo-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client_r18-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-bench-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-bench-debuginfo-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-client-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-client-debuginfo-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-debuginfo-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-debugsource-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-errormessages-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-test-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-test-debuginfo-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-tools-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-tools-debuginfo-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.37-24.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client18-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client18-debuginfo-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client_r18-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-bench-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-bench-debuginfo-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-client-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-client-debuginfo-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-debuginfo-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-debugsource-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-errormessages-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-test-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-test-debuginfo-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-tools-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-tools-debuginfo-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.37-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.37-27.1") ) flag++;

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
