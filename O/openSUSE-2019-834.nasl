#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-834.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123349);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-17336");

  script_name(english:"openSUSE Security Update : udisks2 (openSUSE-2019-834)");
  script_summary(english:"Check for the openSUSE-2019-834 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for udisks2 fixes the following issues :

Following security issues was fixed :

  - CVE-2018-17336: A format string vulnerability in
    udisks_log (bsc#1109406)

Following non-security issues were fixed :

  - strip trailing newline from sysfs raid level information
    (bsc#1091274)

  - Fix watcher error for non-redundant raid devices.
    (bsc#1091274)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109406"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected udisks2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudisks2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudisks2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-UDisks-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udisks2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udisks2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udisks2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udisks2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udisks2-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/22");
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

if ( rpm_check(release:"SUSE15.0", reference:"libudisks2-0-2.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libudisks2-0-debuginfo-2.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-UDisks-2_0-2.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"udisks2-2.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"udisks2-debuginfo-2.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"udisks2-debugsource-2.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"udisks2-devel-2.6.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"udisks2-lang-2.6.5-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libudisks2-0 / libudisks2-0-debuginfo / typelib-1_0-UDisks-2_0 / etc");
}
