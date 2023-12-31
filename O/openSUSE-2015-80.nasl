#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-80.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81064);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-9390");

  script_name(english:"openSUSE Security Update : git (openSUSE-SU-2015:0159-1)");
  script_summary(english:"Check for the openSUSE-2015-80 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issue :

  - CVE-2014-9390: arbitrary command execution vulnerability
    on case-insensitive file system ( bnc#910756)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2015-01/msg00083.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git and Mercurial HTTP Server For CVE-2014-9390');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-remote-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gitk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"git-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-arch-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-core-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-core-debuginfo-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-cvs-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-daemon-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-daemon-debuginfo-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-debugsource-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-email-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-gui-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-remote-helpers-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-svn-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-svn-debuginfo-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-web-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gitk-1.8.4.5-3.8.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-arch-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-core-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-core-debuginfo-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-cvs-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-daemon-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-daemon-debuginfo-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-debugsource-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-email-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-gui-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-svn-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-svn-debuginfo-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-web-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gitk-2.1.4-9.7") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-arch-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-core-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-core-debuginfo-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-cvs-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-daemon-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-daemon-debuginfo-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-debugsource-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-email-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-gui-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-svn-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-svn-debuginfo-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"git-web-2.1.4-9.6") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"gitk-2.1.4-9.6") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git / git-arch / git-core / git-core-debuginfo / git-cvs / etc");
}
