#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-592.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78498);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-3634", "CVE-2014-3683");

  script_name(english:"openSUSE Security Update : rsyslog (openSUSE-SU-2014:1297-1)");
  script_summary(english:"Check for the openSUSE-2014-592 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fixed PRI DoS vulnerability patch
    (CVE-2014-3683,bnc#899756) [*
    rsyslog-7.4.7-remote-PRI-DoS-fix-backport_CVE-2014-3634.
    patch]

  - Removed broken, unsupported and dropped by upstream
    zpipe utility from rsyslog-diag-tools package
    (bnc#890228)

  - Remote syslog PRI DoS vulnerability fix
    (CVE-2014-3634,bnc#897262) [+
    rsyslog-7.4.7-remote-PRI-DoS-fix-backport_CVE-2014-3634.
    patch]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=890228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=899756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2014-10/msg00020.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rsyslog packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-guardtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-guardtime-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-mmnormalize-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-relp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-udpspoof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsyslog-module-udpspoof-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-debugsource-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-diag-tools-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-diag-tools-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-dbi-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-dbi-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-elasticsearch-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-elasticsearch-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-gcrypt-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-gcrypt-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-gssapi-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-gssapi-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-gtls-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-gtls-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-guardtime-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-guardtime-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-mmnormalize-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-mmnormalize-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-mysql-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-mysql-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-pgsql-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-pgsql-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-relp-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-relp-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-snmp-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-snmp-debuginfo-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-udpspoof-7.4.7-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rsyslog-module-udpspoof-debuginfo-7.4.7-2.20.1") ) flag++;

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
