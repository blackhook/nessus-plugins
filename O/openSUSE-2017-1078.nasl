#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1078.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103368);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-14482");

  script_name(english:"openSUSE Security Update : emacs (openSUSE-2017-1078)");
  script_summary(english:"Check for the openSUSE-2017-1078 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for emacs fixes one issues.

This security issue was fixed :

  - CVE-2017-14482: Remote code execution via mails with
    'Content-Type: text/enriched' (bsc#1058425)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058425"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected emacs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-nox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:etags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:etags-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"emacs-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"emacs-debuginfo-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"emacs-debugsource-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"emacs-el-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"emacs-info-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"emacs-nox-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"emacs-nox-debuginfo-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"emacs-x11-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"emacs-x11-debuginfo-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"etags-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"etags-debuginfo-24.3-24.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"emacs-24.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"emacs-debuginfo-24.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"emacs-debugsource-24.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"emacs-el-24.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"emacs-info-24.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"emacs-nox-24.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"emacs-nox-debuginfo-24.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"emacs-x11-24.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"emacs-x11-debuginfo-24.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"etags-24.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"etags-debuginfo-24.3-28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs / emacs-debuginfo / emacs-debugsource / emacs-el / emacs-info / etc");
}
