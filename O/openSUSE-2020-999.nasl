#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-999.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138757);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2020-4044");

  script_name(english:"openSUSE Security Update : xrdp (openSUSE-2020-999)");
  script_summary(english:"Check for the openSUSE-2020-999 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for xrdp fixes the following issues :

  - Security fixes (bsc#1173580, CVE-2020-4044) :

  + Add patches :

  - xrdp-cve-2020-4044-fix-0.patch

  - xrdp-cve-2020-4044-fix-1.patch

  + Rebase SLE patch :

  - xrdp-fate318398-change-expired-password.patch

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173580"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xrdp packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpainter0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpainter0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librfxencode0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librfxencode0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xrdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xrdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xrdp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xrdp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libpainter0-0.9.6-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpainter0-debuginfo-0.9.6-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librfxencode0-0.9.6-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librfxencode0-debuginfo-0.9.6-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"xrdp-0.9.6-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"xrdp-debuginfo-0.9.6-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"xrdp-debugsource-0.9.6-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"xrdp-devel-0.9.6-lp151.4.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpainter0 / libpainter0-debuginfo / librfxencode0 / etc");
}
