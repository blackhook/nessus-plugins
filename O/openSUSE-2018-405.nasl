#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-405.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109424);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-2755", "CVE-2018-2758", "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2771", "CVE-2018-2773", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787", "CVE-2018-2805", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2818", "CVE-2018-2819");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2018-405)");
  script_summary(english:"Check for the openSUSE-2018-405 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mysql-community-server to version 5.6.40 fixes the
following issues :

Security issues fixed :

  - CVE-2018-2755: Unspecified vulnerability in the
    Replication component

  - CVE-2018-2819: Unspecified vulnerability in the InnoDB
    component

  - CVE-2018-2817: Unspecified vulnerability in the Server
    DDL component

  - CVE-2018-2761: Unspecified vulnerability in the client
    programs

  - CVE-2018-2818: Unspecified vulnerability in the Server
    Security Privileges component

  - CVE-2018-2781: Unspecified vulnerability in the Server
    Optimizer component

  - CVE-2018-2771: Unspecified vulnerability in the Server
    locking component

  - CVE-2018-2813: Unspecified vulnerability in the Server
    DDL component

  - CVE-2018-2773: Unspecified vulnerability in the client
    programs

  - CVE-2018-2758: Unspecified vulnerability in the Server
    Security Privileges component

  - CVE-2018-2805: Unspecified vulnerability in the GIS
    Extension

  - CVE-2018-2782: Unspecified vulnerability in the InnoDB
    component

  - CVE-2018-2784: Unspecified vulnerability in the InnoDB
    component

  - CVE-2018-2787: Unspecified vulnerability in the InnoDB
    component

  - CVE-2018-2766: Unspecified vulnerability in the InnoDB
    component

This update also contains all upstream fixes and improvement in the
5.6.40 release:
http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-40.html"
  );
  # http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-40.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-40.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089987"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/30");
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

if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client18-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client18-debuginfo-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client_r18-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-bench-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-bench-debuginfo-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-client-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-client-debuginfo-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-debuginfo-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-debugsource-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-errormessages-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-test-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-test-debuginfo-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-tools-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-tools-debuginfo-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.40-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.40-36.1") ) flag++;

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
