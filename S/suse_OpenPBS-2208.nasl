#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update OpenPBS-2208.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27141);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"openSUSE 10 Security Update : OpenPBS (OpenPBS-2208)");
  script_summary(english:"Check for the OpenPBS-2208 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of OpenPBS fixes some potential security vulnerabilities
that may allow the compromising of a system remotely and/or locally."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenPBS packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenPBS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenPBS-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenPBS-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenPBS-mom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenPBS-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenPBS-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenPBS-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"OpenPBS-2.3.16-627.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenPBS-clients-2.3.16-627.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenPBS-devel-2.3.16-627.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenPBS-mom-2.3.16-627.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenPBS-scheduler-2.3.16-627.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenPBS-server-2.3.16-627.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenPBS-utils-2.3.16-627.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenPBS");
}
