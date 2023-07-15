#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-855.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111636);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : blueman (openSUSE-2018-855)");
  script_summary(english:"Check for the openSUSE-2018-855 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for blueman fixes the following issues :

The following security issue was addressed :

  - Fixed the polkit authorization checks in blueman, which
    previously allowed any user with access to the D-Bus
    system bus to trigger certain network configuration
    logic in blueman without authentication (boo#1083066)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083066"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected blueman packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:blueman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:blueman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:blueman-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:blueman-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:thunar-sendto-blueman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/10");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"blueman-2.0.6-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"blueman-debuginfo-2.0.6-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"blueman-debugsource-2.0.6-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"blueman-lang-2.0.6-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"thunar-sendto-blueman-2.0.6-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"blueman-2.0.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"blueman-debuginfo-2.0.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"blueman-debugsource-2.0.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"blueman-lang-2.0.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"thunar-sendto-blueman-2.0.6-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "blueman / blueman-debuginfo / blueman-debugsource / blueman-lang / etc");
}
