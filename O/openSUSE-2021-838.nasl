#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-838.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150319);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id("CVE-2021-3560");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"openSUSE Security Update : polkit (openSUSE-2021-838)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for polkit fixes the following issues :

  - CVE-2021-3560: Fixed a local privilege escalation using
    polkit_system_bus_name_get_creds_sync() (bsc#1186497).

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186497");
  script_set_attribute(attribute:"solution", value:
"Update the affected polkit packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3560");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Polkit D-Bus Authentication Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Polkit-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libpolkit0-0.116-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpolkit0-debuginfo-0.116-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"polkit-0.116-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"polkit-debuginfo-0.116-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"polkit-debugsource-0.116-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"polkit-devel-0.116-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"polkit-devel-debuginfo-0.116-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-Polkit-1_0-0.116-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libpolkit0-32bit-0.116-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libpolkit0-32bit-debuginfo-0.116-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpolkit0 / libpolkit0-debuginfo / polkit / polkit-debuginfo / etc");
}
