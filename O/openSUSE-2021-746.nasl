#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-746.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149542);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_name(english:"openSUSE Security Update : dtc (openSUSE-2021-746)");
  script_summary(english:"Check for the openSUSE-2021-746 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for dtc fixes the following issues :

  - make all packaged binaries PIE-executables
    (bsc#1184122).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184122"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dtc packages.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dtc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdt1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdt1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdt1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libfdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libfdt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"dtc-1.5.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dtc-debuginfo-1.5.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dtc-debugsource-1.5.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfdt-devel-1.5.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfdt1-1.5.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfdt1-debuginfo-1.5.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-libfdt-1.5.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-libfdt-debuginfo-1.5.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libfdt-devel-32bit-1.5.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libfdt1-32bit-1.5.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libfdt1-32bit-debuginfo-1.5.1-lp152.2.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dtc / dtc-debuginfo / dtc-debugsource / libfdt-devel / libfdt1 / etc");
}
