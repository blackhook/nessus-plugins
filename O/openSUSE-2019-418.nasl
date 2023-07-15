#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-418.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123180);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2018-3639");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2019-418) (Meltdown) (Spectre)");
  script_summary(english:"Check for the openSUSE-2019-418 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen to version 4.10.1 fixes several issues
(bsc#1027519).

These security issues were fixed :

  - CVE-2018-3639: Prevent attackers with local user access
    from extracting information via a side-channel analysis,
    aka Speculative Store Bypass (SSB), Variant 4
    (bsc#1092631).

  - CVE-2017-5753,CVE-2017-5715,CVE-2017-5754: Improved
    Spectre v2 mitigations (bsc#1074562).

This non-security issue was fixed :

  - Always call qemus xen-save-devices-state in
    suspend/resume to fix migration with qcow2 images
    (bsc#1079730)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092631"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3639");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

if ( rpm_check(release:"SUSE15.0", reference:"xen-debugsource-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-devel-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-libs-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-libs-debuginfo-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-tools-domU-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xen-tools-domU-debuginfo-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-doc-html-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-libs-32bit-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-libs-32bit-debuginfo-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-tools-4.10.1_04-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.10.1_04-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-debugsource / xen-devel / xen-doc-html / xen-libs-32bit / etc");
}
