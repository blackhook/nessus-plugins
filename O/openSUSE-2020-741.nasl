#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-741.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136995);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/05");

  script_cve_id("CVE-2019-13508");

  script_name(english:"openSUSE Security Update : freetds (openSUSE-2020-741)");
  script_summary(english:"Check for the openSUSE-2020-741 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for freetds to 1.1.36 fixes the following issues :

Security issue fixed :

  - CVE-2019-13508: Fixed a heap overflow that could have
    been caused by malicious servers sending UDT types over
    protocol version 5.0 (bsc#1141132).

Non-security issues fixed :

  - Enabled Kerberos support

  - Version update to 1.1.36 :

  - Default TDS protocol version is now 'auto'

  - Improved UTF-8 performances

  - TDS Pool Server is enabled

  - MARS support is enabled

  - NTLMv2 is enabled

  - See NEWS and ChangeLog for a complete list of changes

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141132"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected freetds packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetds-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetds-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetds-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetds-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetds-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libct4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libct4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsybdb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsybdb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdsodbc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdsodbc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/31");
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

if ( rpm_check(release:"SUSE15.1", reference:"freetds-config-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freetds-debuginfo-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freetds-debugsource-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freetds-devel-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freetds-tools-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freetds-tools-debuginfo-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libct4-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libct4-debuginfo-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsybdb5-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsybdb5-debuginfo-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libtdsodbc0-1.1.36-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libtdsodbc0-debuginfo-1.1.36-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetds-config / freetds-debuginfo / freetds-debugsource / etc");
}
