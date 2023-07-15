#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-289.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(134280);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/10");

  script_cve_id("CVE-2019-18901", "CVE-2020-2574");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2020-289)");
  script_summary(english:"Check for the openSUSE-2020-289 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mariadb fixes the following issues :

MariaDB was updated to version 10.2.31 GA (bsc#1162388).

Security issues fixed :

  - CVE-2020-2574: Fixed a difficult to exploit
    vulnerability that allowed an attacker to crash the
    client (bsc#1162388).

  - CVE-2019-18901: Fixed an unsafe path handling behavior
    in mysql-systemd-helper (bsc#1160895).

  - Enabled security hardenings in MariaDB's systemd
    service, namely ProtectSystem, ProtectHome and UMask
    (bsc#1160878).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162388"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18901");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libmysqld-devel-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmysqld19-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmysqld19-debuginfo-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-bench-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-bench-debuginfo-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-client-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-client-debuginfo-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-debuginfo-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-debugsource-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-errormessages-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-galera-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-test-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-test-debuginfo-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-tools-10.2.31-lp151.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-tools-debuginfo-10.2.31-lp151.2.12.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqld-devel / libmysqld19 / libmysqld19-debuginfo / mariadb / etc");
}
