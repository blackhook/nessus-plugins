#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-42.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106069);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : gifsicle (openSUSE-2018-42)");
  script_summary(english:"Check for the openSUSE-2018-42 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gifsicle to version 1.91 fixes several issues.

These security issues were fixed :

  - Prevent double free by setting last_name to NULL

  - Prevent NULL pointer dereference for crafted images

This non-security issue was fixed :

  - Add thread support for resizing

For other changes please see the upstream changelog."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gifsicle packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gifsicle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gifsicle-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gifsicle-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/16");
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

if ( rpm_check(release:"SUSE42.2", reference:"gifsicle-1.91-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gifsicle-debuginfo-1.91-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gifsicle-debugsource-1.91-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gifsicle-1.91-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gifsicle-debuginfo-1.91-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gifsicle-debugsource-1.91-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gifsicle / gifsicle-debuginfo / gifsicle-debugsource");
}
