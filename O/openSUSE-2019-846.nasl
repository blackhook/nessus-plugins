#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-846.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123353);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-18065");

  script_name(english:"openSUSE Security Update : net-snmp (openSUSE-2019-846)");
  script_summary(english:"Check for the openSUSE-2019-846 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for net-snmp fixes the following issues :

Security issues fixed :

  - CVE-2018-18065: _set_key in
    agent/helpers/table_container.c had a NULL pointer
    Exception bug that can be used by an authenticated
    attacker to remotely cause the instance to crash via a
    crafted UDP packet, resulting in Denial of Service.
    (bsc#1111122)

Non-security issues fixed :

  - swintst_rpm: Protect against unspecified Group name
    (bsc#1102775)

  - Add tsm and tlstm MIBs and the USM security module.
    (bsc#1081164)

  - Fix agentx freezing on timeout (bsc#1027353)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111122"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-SNMP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-SNMP-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
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

if ( rpm_check(release:"SUSE15.0", reference:"libsnmp30-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsnmp30-debuginfo-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"net-snmp-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"net-snmp-debuginfo-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"net-snmp-debugsource-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"net-snmp-devel-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-SNMP-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-SNMP-debuginfo-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python2-net-snmp-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python2-net-snmp-debuginfo-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-net-snmp-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-net-snmp-debuginfo-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"snmp-mibs-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsnmp30-32bit-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsnmp30-32bit-debuginfo-5.7.3-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"net-snmp-devel-32bit-5.7.3-lp150.6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsnmp30-32bit / libsnmp30-32bit-debuginfo / libsnmp30 / etc");
}
