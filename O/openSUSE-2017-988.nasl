#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-988.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102943);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000117");

  script_name(english:"openSUSE Security Update : git (openSUSE-2017-988)");
  script_summary(english:"Check for the openSUSE-2017-988 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for git fixes the following issues :

  - CVE-2017-1000117: A client side code execution via shell
    injection when receiving special submodule strings from
    a malicious server was fixed (bsc#1052481)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052481"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git HTTP Server For CVE-2017-1000117');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-credential-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-credential-gnome-keyring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gitk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"git-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-arch-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-core-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-core-debuginfo-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-credential-gnome-keyring-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-credential-gnome-keyring-debuginfo-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-cvs-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-daemon-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-daemon-debuginfo-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-debugsource-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-email-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-gui-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-svn-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-svn-debuginfo-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"git-web-2.12.3-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gitk-2.12.3-5.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git / git-arch / git-core / git-core-debuginfo / etc");
}
