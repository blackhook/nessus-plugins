#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-738.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136994);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/28");

  script_cve_id("CVE-2020-13249");

  script_name(english:"openSUSE Security Update : mariadb-connector-c (openSUSE-2020-738)");
  script_summary(english:"Check for the openSUSE-2020-738 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mariadb-connector-c fixes the following issues :

Security issue fixed :

  - CVE-2020-13249: Fixed an improper validation of OK
    packets received from clients (bsc#1171550).

Non-security issues fixed :

  - Update to release 3.1.8 (bsc#1171550)

  - CONC-304: Rename the static library to libmariadb.a and
    other libmariadb files in a consistent manner

  - CONC-441: Default user name for C/C is wrong if login
    user is different from effective user

  - CONC-449: Check $MARIADB_HOME/my.cnf in addition to
    $MYSQL_HOME/my.cnf

  - CONC-457: mysql_list_processes crashes in unpack_fields

  - CONC-458: mysql_get_timeout_value crashes when used
    improper

  - CONC-464: Fix static build for auth_gssapi_client plugin

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171550"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected mariadb-connector-c packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13249");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb_plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadb_plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbprivate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbprivate-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-connector-c-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/01");
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

if ( rpm_check(release:"SUSE15.1", reference:"libmariadb-devel-3.1.8-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadb-devel-debuginfo-3.1.8-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadb3-3.1.8-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadb3-debuginfo-3.1.8-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadb_plugins-3.1.8-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadb_plugins-debuginfo-3.1.8-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadbprivate-3.1.8-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmariadbprivate-debuginfo-3.1.8-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mariadb-connector-c-debugsource-3.1.8-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libmariadb3-32bit-3.1.8-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libmariadb3-32bit-debuginfo-3.1.8-lp151.3.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmariadb-devel / libmariadb-devel-debuginfo / libmariadb3 / etc");
}
