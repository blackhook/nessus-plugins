#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-13.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105713);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : gimp (openSUSE-2018-13)");
  script_summary(english:"Check for the openSUSE-2018-13 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gimp fixes the following issues :

  - Don't build gimp with webkit1 support, as it is no
    longer maintained and has plenty of security bugs. 

    This disables the GIMP's built-in help browser; it will
    use an external browser when configured this way.

    This works around a number of security vulnerabilities
    in Webkit1.

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050469"
  );
  # https://features.opensuse.org/323744
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugin-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugin-aa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugins-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugins-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/10");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"gimp-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gimp-debuginfo-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gimp-debugsource-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gimp-devel-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gimp-devel-debuginfo-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gimp-lang-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gimp-plugin-aa-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gimp-plugin-aa-debuginfo-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gimp-plugins-python-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gimp-plugins-python-debuginfo-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgimp-2_0-0-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgimp-2_0-0-debuginfo-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgimpui-2_0-0-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgimpui-2_0-0-debuginfo-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgimp-2_0-0-32bit-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgimp-2_0-0-debuginfo-32bit-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgimpui-2_0-0-32bit-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgimpui-2_0-0-debuginfo-32bit-2.8.18-2.6.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gimp-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gimp-debuginfo-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gimp-debugsource-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gimp-devel-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gimp-devel-debuginfo-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gimp-lang-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gimp-plugin-aa-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gimp-plugin-aa-debuginfo-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gimp-plugins-python-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gimp-plugins-python-debuginfo-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgimp-2_0-0-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgimp-2_0-0-debuginfo-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgimpui-2_0-0-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgimpui-2_0-0-debuginfo-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgimp-2_0-0-32bit-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgimp-2_0-0-debuginfo-32bit-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgimpui-2_0-0-32bit-2.8.18-6.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgimpui-2_0-0-debuginfo-32bit-2.8.18-6.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-debuginfo / gimp-debugsource / gimp-devel / etc");
}
