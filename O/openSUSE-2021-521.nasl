#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-521.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148412);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/09");

  script_name(english:"openSUSE Security Update : fwupdate (openSUSE-2021-521)");
  script_summary(english:"Check for the openSUSE-2021-521 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for fwupdate fixes the following issues :

  - Add SBAT section to EFI images (bsc#1182057)

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182057"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected fwupdate packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupdate-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupdate-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupdate-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupdate-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupdate-efi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfwup1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfwup1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/09");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"fwupdate-12-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fwupdate-debuginfo-12-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fwupdate-debugsource-12-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fwupdate-devel-12-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fwupdate-efi-12-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fwupdate-efi-debuginfo-12-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfwup1-12-lp152.6.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfwup1-debuginfo-12-lp152.6.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fwupdate / fwupdate-debuginfo / fwupdate-debugsource / etc");
}
