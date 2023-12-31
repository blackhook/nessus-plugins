#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-276.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74626);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2009-5026", "CVE-2012-0583", "CVE-2012-1688", "CVE-2012-1690", "CVE-2012-1696", "CVE-2012-1697", "CVE-2012-1703");

  script_name(english:"openSUSE Security Update : mysql-cluster (openSUSE-SU-2012:0617-1)");
  script_summary(english:"Check for the openSUSE-2012-276 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MySQL Cluster 7.1.21 fixes several security issues and bugs. Please
refer to the following upstream announcement for details :

http://dev.mysql.com/doc/refman/5.1/en/mysql-cluster-news-7-1.html"
  );
  # http://dev.mysql.com/doc/refman/5.1/en/mysql-cluster-news-7-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/refman/5.1/en/mysql-cluster-news-7-1.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=675870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2012-05/msg00018.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-cluster packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclusterclient16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclusterclient16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclusterclient_r16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclusterclient_r16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-ndb-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-ndb-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-ndb-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-ndb-management-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-ndb-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-ndb-storage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-ndb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-ndb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-cluster-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclusterclient16-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclusterclient16-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclusterclient_r16-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclusterclient_r16-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-bench-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-bench-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-client-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-client-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-debug-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-debug-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-debugsource-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-ndb-extra-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-ndb-extra-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-ndb-management-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-ndb-management-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-ndb-storage-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-ndb-storage-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-ndb-tools-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-ndb-tools-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-test-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-test-debuginfo-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-tools-7.1.21-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-cluster-tools-debuginfo-7.1.21-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclusterclient16 / libmysqlclusterclient16-debuginfo / etc");
}
