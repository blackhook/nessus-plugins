#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1037.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117685);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-14424");

  script_name(english:"openSUSE Security Update : gdm (openSUSE-2018-1037)");
  script_summary(english:"Check for the openSUSE-2018-1037 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gdm provides the following fixes :

This security issue was fixed :

  - CVE-2018-14424: The daemon in GDM did not properly
    unexport display objects from its D-Bus interface when
    they are destroyed, which allowed a local attacker to
    trigger a use-after-free via a specially crafted
    sequence of D-Bus method calls, resulting in a denial of
    service or potential code execution (bsc#1103737)

These non-security issues were fixed :

  - Enable pam_keyinit module (bsc#1081947)

  - Fix a build race in SLE (bsc#1103093)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103737"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/25");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"gdm-3.26.2.1-lp150.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdm-branding-upstream-3.26.2.1-lp150.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdm-debuginfo-3.26.2.1-lp150.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdm-debugsource-3.26.2.1-lp150.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdm-devel-3.26.2.1-lp150.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdm-lang-3.26.2.1-lp150.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdmflexiserver-3.26.2.1-lp150.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgdm1-3.26.2.1-lp150.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgdm1-debuginfo-3.26.2.1-lp150.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-Gdm-1_0-3.26.2.1-lp150.11.3.1") ) flag++;

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
