#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-91.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106360);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-8859");

  script_name(english:"openSUSE Security Update : tre (openSUSE-2018-91)");
  script_summary(english:"Check for the openSUSE-2018-91 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tre fixes one issue.

This security issue was fixed :

  - CVE-2016-8859: Fixed multiple integer overflows which
    allowed attackers to cause memory corruption via a large
    number of (1) states or (2) tags, which triggered an
    out-of-bounds write (boo#1005483)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005483"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tre packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:agrep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:agrep-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtre5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtre5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tre-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tre-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tre-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tre-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.2", reference:"agrep-0.8.0_git201402282055-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"agrep-debuginfo-0.8.0_git201402282055-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtre5-0.8.0_git201402282055-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtre5-debuginfo-0.8.0_git201402282055-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-tre-0.8.0_git201402282055-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-tre-debuginfo-0.8.0_git201402282055-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tre-0.8.0_git201402282055-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tre-debugsource-0.8.0_git201402282055-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tre-devel-0.8.0_git201402282055-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tre-lang-0.8.0_git201402282055-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"agrep-0.8.0_git201402282055-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"agrep-debuginfo-0.8.0_git201402282055-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtre5-0.8.0_git201402282055-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtre5-debuginfo-0.8.0_git201402282055-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-tre-0.8.0_git201402282055-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-tre-debuginfo-0.8.0_git201402282055-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tre-0.8.0_git201402282055-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tre-debugsource-0.8.0_git201402282055-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tre-devel-0.8.0_git201402282055-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tre-lang-0.8.0_git201402282055-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "agrep / agrep-debuginfo / libtre5 / libtre5-debuginfo / python-tre / etc");
}
