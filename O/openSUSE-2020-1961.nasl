#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1961.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143134);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2020-16125");

  script_name(english:"openSUSE Security Update : gdm (openSUSE-2020-1961)");
  script_summary(english:"Check for the openSUSE-2020-1961 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gdm fixes the following issues :

  - Exit with failure if loading existing users fails
    (bsc#1178150 CVE-2020-16125).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178150"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdmflexiserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Gdm-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"gdm-3.34.1-lp152.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdm-branding-upstream-3.34.1-lp152.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdm-debuginfo-3.34.1-lp152.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdm-debugsource-3.34.1-lp152.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdm-devel-3.34.1-lp152.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdm-lang-3.34.1-lp152.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdm-systemd-3.34.1-lp152.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdmflexiserver-3.34.1-lp152.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgdm1-3.34.1-lp152.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgdm1-debuginfo-3.34.1-lp152.6.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-Gdm-1_0-3.34.1-lp152.6.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm / gdm-branding-upstream / gdm-debuginfo / gdm-debugsource / etc");
}
