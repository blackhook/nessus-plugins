#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1734.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(142039);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-15999");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"openSUSE Security Update : freetype2 (openSUSE-2020-1734)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for freetype2 fixes the following issues :

  - CVE-2020-15999: fixed a heap buffer overflow found in
    the handling of embedded PNG bitmaps (bsc#1177914).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177914");
  script_set_attribute(attribute:"solution", value:
"Update the affected freetype2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-profile-tti35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ft2demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftbench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftdiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftgrid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftinspect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftlint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftmulti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftvalid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ftview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"freetype2-debugsource-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freetype2-devel-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freetype2-profile-tti35-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreetype6-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreetype6-debuginfo-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"freetype2-devel-32bit-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ft2demos-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftbench-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftdiff-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftdump-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftgamma-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftgrid-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftinspect-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftlint-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftmulti-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftstring-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftvalid-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"ftview-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreetype6-32bit-2.10.1-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreetype6-32bit-debuginfo-2.10.1-lp151.4.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype2-debugsource / freetype2-devel / freetype2-profile-tti35 / etc");
}
