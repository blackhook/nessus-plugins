#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update cron-4495.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75804);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"openSUSE Security Update : cron (openSUSE-SU-2011:0452-1)");
  script_summary(english:"Check for the cron-4495 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"Cronie does not drop all privileges before calling sendmail."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=690166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2011-05/msg00012.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cron packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cronie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cronie-anacron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cronie-anacron-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cronie-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cronie-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"cron-4.2-9.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"cronie-1.4.7-9.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"cronie-anacron-1.4.7-9.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"cronie-anacron-debuginfo-1.4.7-9.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"cronie-debuginfo-1.4.7-9.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"cronie-debugsource-1.4.7-9.19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Cronie");
}
