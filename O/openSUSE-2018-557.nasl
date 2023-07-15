#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-557.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110335);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-11233", "CVE-2018-11235");

  script_name(english:"openSUSE Security Update : git (openSUSE-2018-557)");
  script_summary(english:"Check for the openSUSE-2018-557 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for fixes the following security issues :

  - path sanity-checks on NTFS can read arbitrary memory
    (CVE-2018-11233, boo#1095218)

  - arbitrary code execution when recursively cloning a
    malicious repository (CVE-2018-11235, boo#1095219)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095219"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-credential-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-credential-gnome-keyring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-credential-libsecret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-credential-libsecret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gitk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"git-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-arch-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-core-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-core-debuginfo-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-credential-gnome-keyring-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-credential-gnome-keyring-debuginfo-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-credential-libsecret-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-credential-libsecret-debuginfo-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-cvs-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-daemon-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-daemon-debuginfo-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-debuginfo-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-debugsource-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-email-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-gui-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-p4-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-svn-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-svn-debuginfo-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"git-web-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gitk-2.16.4-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-arch-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-core-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-core-debuginfo-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-credential-gnome-keyring-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-credential-gnome-keyring-debuginfo-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-cvs-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-daemon-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-daemon-debuginfo-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-debugsource-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-email-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-gui-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-svn-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-svn-debuginfo-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"git-web-2.13.7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gitk-2.13.7-13.1") ) flag++;

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
