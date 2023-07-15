#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-170.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145525);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/18");

  script_cve_id("CVE-2021-3156", "CVE-2021-23239", "CVE-2021-23240");
  script_xref(name:"IAVA", value:"2021-A-0053");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/27");

  script_name(english:"openSUSE Security Update : sudo (openSUSE-2021-170)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for sudo fixes the following issues :

  - A Heap-based buffer overflow in sudo could be exploited
    to allow a user to gain root privileges
    [bsc#1181090,CVE-2021-3156]

  - It was possible for a user to test for the existence of
    a directory due to a Race Condition in `sudoedit`
    [bsc#1180684,CVE-2021-23239]

  - A Possible Symlink Attack vector existed in `sudoedit`
    if SELinux was running in permissive mode [bsc#1180685,
    CVE-2021-23240]

  - It was possible for a User to enable Debug Settings not
    Intended for them [bsc#1180687]

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181090");
  script_set_attribute(attribute:"solution", value:
"Update the affected sudo packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3156");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sudo Heap-Based Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sudo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sudo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sudo-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE15.2", reference:"sudo-1.8.22-lp152.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sudo-debuginfo-1.8.22-lp152.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sudo-debugsource-1.8.22-lp152.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sudo-devel-1.8.22-lp152.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sudo-test-1.8.22-lp152.8.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo / sudo-debuginfo / sudo-debugsource / sudo-devel / sudo-test");
}
