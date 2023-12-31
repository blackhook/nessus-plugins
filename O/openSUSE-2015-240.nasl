#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-240.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81963);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : gdm (openSUSE-2015-240)");
  script_summary(english:"Check for the openSUSE-2015-240 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The GNOME Display Manager was updated to fix one security issue :

  - Removed gdm-fingerprint and gdm-smartcard pamfiles that
    allowed unlocking the screen without password or
    fingerprint if fingerprint reader support was enabled.
    (boo#900836)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900836"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdm packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdmflexiserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Gdm-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"gdm-3.14.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdm-branding-upstream-3.14.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdm-debuginfo-3.14.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdm-debugsource-3.14.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdm-devel-3.14.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdm-lang-3.14.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gdmflexiserver-3.14.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgdm1-3.14.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgdm1-debuginfo-3.14.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-Gdm-1_0-3.14.1-4.1") ) flag++;

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
