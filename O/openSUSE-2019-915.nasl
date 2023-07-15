#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-915.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123375);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-14665");

  script_name(english:"openSUSE Security Update : xorg-x11-server (openSUSE-2019-915)");
  script_summary(english:"Check for the openSUSE-2019-915 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xorg-x11-server fixes the following issues :

  - CVE-2018-14665: Disable -logfile and -modulepath when
    running with elevated privileges (bsc#1112020, 

    Note that SUSE by default does not run with elevated
    privileges, so the default installation is not affected
    by this problem.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112020"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Xorg X11 Server SUID modulepath Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-wayland-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/25");
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

if ( rpm_check(release:"SUSE15.0", reference:"xorg-x11-server-1.19.6-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xorg-x11-server-debuginfo-1.19.6-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xorg-x11-server-debugsource-1.19.6-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xorg-x11-server-extra-1.19.6-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xorg-x11-server-extra-debuginfo-1.19.6-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xorg-x11-server-sdk-1.19.6-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xorg-x11-server-source-1.19.6-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xorg-x11-server-wayland-1.19.6-lp150.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"xorg-x11-server-wayland-debuginfo-1.19.6-lp150.7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server / xorg-x11-server-debuginfo / etc");
}
