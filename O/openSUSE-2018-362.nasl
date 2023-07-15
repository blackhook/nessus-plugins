#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-362.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109023);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1063");

  script_name(english:"openSUSE Security Update : policycoreutils (openSUSE-2018-362)");
  script_summary(english:"Check for the openSUSE-2018-362 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for policycoreutils fixes the following issues :

  - CVE-2018-1063: Fixed problem to prevent chcon from
    following symlinks in /tmp, /var/tmp, /var/run and
    /var/lib/debug (bsc#1083624).

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083624"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected policycoreutils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils-newrole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils-newrole-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:policycoreutils-sandbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/13");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-2.5-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-debuginfo-2.5-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-debugsource-2.5-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-gui-2.5-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-lang-2.5-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-newrole-2.5-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-newrole-debuginfo-2.5-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-python-2.5-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-python-debuginfo-2.5-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-sandbox-2.5-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"policycoreutils-sandbox-debuginfo-2.5-6.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "policycoreutils / policycoreutils-debuginfo / etc");
}
