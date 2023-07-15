#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-671.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100738);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-3469");

  script_name(english:"openSUSE Security Update : mysql-connector-cpp / mysql-workbench (openSUSE-2017-671)");
  script_summary(english:"Check for the openSUSE-2017-671 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mysql-connector-cpp and mysql-workbench fixes the
following issues :

Mysql-connector-cpp was updated to version 1.1.8 :

  - See the news files on
    https://dev.mysql.com/doc/relnotes/connector-cpp/en/

Mysql-workbench was updated to version 6.3.9 :

- https://dev.mysql.com/doc/relnotes/workbench/en/wb-news-6-3-8.html

- https://dev.mysql.com/doc/relnotes/workbench/en/wb-news-6-3-9.html

  - resolves CVE-2017-3469 (boo#1035195)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/connector-cpp/en/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/workbench/en/wb-news-6-3-8.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/workbench/en/wb-news-6-3-9.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-connector-cpp / mysql-workbench packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlcppconn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlcppconn7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlcppconn7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-connector-cpp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-workbench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-workbench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-workbench-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.2", reference:"libmysqlcppconn-devel-1.1.8-5.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlcppconn7-1.1.8-5.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlcppconn7-debuginfo-1.1.8-5.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-connector-cpp-debugsource-1.1.8-5.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mysql-workbench-6.3.9-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mysql-workbench-debuginfo-6.3.9-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mysql-workbench-debugsource-6.3.9-2.5.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlcppconn-devel / libmysqlcppconn7 / etc");
}
