#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-991.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123407);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-4700");

  script_name(english:"openSUSE Security Update : cups (openSUSE-2019-991)");
  script_summary(english:"Check for the openSUSE-2019-991 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cups fixes the following issues :

Security issue fixed :

  - CVE-2018-4700: Fixed extremely predictable cookie
    generation that is effectively breaking the CSRF
    protection of the CUPS web interface (bsc#1115750).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115750"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-ddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-ddk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcups2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcups2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcups2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupscgi1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupscgi1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupscgi1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsimage2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsimage2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsimage2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsmime1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsmime1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsmime1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsppdc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsppdc1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsppdc1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcupsppdc1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/05");
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

if ( rpm_check(release:"SUSE15.0", reference:"cups-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cups-client-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cups-client-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cups-config-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cups-ddk-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cups-ddk-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cups-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cups-debugsource-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cups-devel-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcups2-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcups2-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcupscgi1-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcupscgi1-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcupsimage2-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcupsimage2-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcupsmime1-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcupsmime1-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcupsppdc1-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcupsppdc1-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"cups-devel-32bit-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcups2-32bit-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcups2-32bit-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcupscgi1-32bit-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcupscgi1-32bit-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcupsimage2-32bit-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcupsimage2-32bit-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcupsmime1-32bit-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcupsmime1-32bit-debuginfo-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcupsppdc1-32bit-2.2.7-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcupsppdc1-32bit-debuginfo-2.2.7-lp150.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-client / cups-client-debuginfo / cups-config / cups-ddk / etc");
}
