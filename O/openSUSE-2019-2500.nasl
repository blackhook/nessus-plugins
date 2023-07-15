#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2500.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131009);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2019-17041", "CVE-2019-17042");

  script_name(english:"openSUSE Security Update : rsyslog (openSUSE-2019-2500)");
  script_summary(english:"Check for the openSUSE-2019-2500 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for rsyslog fixes the following issues :

Security issues fixed :

  - CVE-2019-17041: Fixed a heap overflow in the parser for
    AIX log messages (bsc#1153451).

  - CVE-2019-17042: Fixed a heap overflow in the parser for
    Cisco log messages (bsc#1153459).

Other issue addressed :

  - Fixed an issue where rsyslog was SEGFAULT due to a mutex
    double-unlock (bsc#1141063). 

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153459"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rsyslog packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-diag-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-diag-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-dbi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-elasticsearch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-gcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-gcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-gssapi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-gtls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-gtls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-mmnormalize-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-omamqp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-omamqp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-omhttpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-omhttpfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-omtcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-omtcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-relp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-udpspoof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-udpspoof-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-debugsource-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-diag-tools-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-diag-tools-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-dbi-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-dbi-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-elasticsearch-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-elasticsearch-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-gcrypt-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-gcrypt-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-gssapi-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-gssapi-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-gtls-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-gtls-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-mmnormalize-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-mmnormalize-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-mysql-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-mysql-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-omamqp1-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-omamqp1-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-omhttpfs-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-omhttpfs-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-omtcl-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-omtcl-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-pgsql-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-pgsql-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-relp-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-relp-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-snmp-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-snmp-debuginfo-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-udpspoof-8.33.1-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"rsyslog-module-udpspoof-debuginfo-8.33.1-lp150.2.19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog / rsyslog-debuginfo / rsyslog-debugsource / etc");
}
