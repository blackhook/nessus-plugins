#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-90.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121429);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : PackageKit (openSUSE-2019-90)");
  script_summary(english:"Check for the openSUSE-2019-90 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for PackageKit fixes the following issues :

  - Fixed displaying the license agreement pop up window
    during package update (bsc#1038425).

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038425"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected PackageKit packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-backend-zypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-backend-zypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gstreamer-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gtk3-module-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-PackageKitGlib-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-backend-zypp-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-backend-zypp-debuginfo-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-branding-upstream-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-debuginfo-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-debugsource-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-devel-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-devel-debuginfo-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-gstreamer-plugin-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-gstreamer-plugin-debuginfo-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-gtk3-module-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-gtk3-module-debuginfo-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"PackageKit-lang-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpackagekit-glib2-18-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpackagekit-glib2-18-debuginfo-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libpackagekit-glib2-devel-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-PackageKitGlib-1_0-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpackagekit-glib2-18-32bit-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpackagekit-glib2-18-debuginfo-32bit-1.1.3-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libpackagekit-glib2-devel-32bit-1.1.3-5.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit / PackageKit-backend-zypp / etc");
}
