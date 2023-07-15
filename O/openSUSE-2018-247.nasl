#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-247.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107286);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7555");

  script_name(english:"openSUSE Security Update : augeas (openSUSE-2018-247)");
  script_summary(english:"Check for the openSUSE-2018-247 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for augeas fixes the following issues :

Security issue fixed :

  - CVE-2017-7555: Fix a memory corruption bug could have
    lead to arbitrary code execution by passing crafted
    strings that would be mis-handled by parse_name()
    (bsc#1054171).

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054171"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected augeas packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas-lense-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:augeas-lenses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaugeas0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaugeas0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaugeas0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaugeas0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/12");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"augeas-1.2.0-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"augeas-debuginfo-1.2.0-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"augeas-debugsource-1.2.0-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"augeas-devel-1.2.0-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"augeas-lense-tests-1.2.0-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"augeas-lenses-1.2.0-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libaugeas0-1.2.0-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libaugeas0-debuginfo-1.2.0-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"augeas-devel-32bit-1.2.0-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libaugeas0-32bit-1.2.0-13.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libaugeas0-debuginfo-32bit-1.2.0-13.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "augeas / augeas-debuginfo / augeas-debugsource / augeas-devel / etc");
}
