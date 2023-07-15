#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-731.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101132);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : libqt5-qtbase / libqt5-qtdeclarative (openSUSE-2017-731)");
  script_summary(english:"Check for the openSUSE-2017-731 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libqt5-qtbase and libqt5-qtdeclarative fixes the
following issues :

This security issue was fixed :

  - Prevent potential information leak due to race condition
    in QSaveFile (bsc#1034005).

These non-security issues were fixed :

  - Fixed crash in QPlainTextEdit

  - Fixed Burmese rendering issue

  - Fixed reuse of C++-owned QObjects by different QML
    engines that could lead to crashes in kwin (bsc#1034402)

  - Make libqt5-qtquickcontrols available in SUSE Linux
    Enterprise.

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034402"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libqt5-qtbase / libqt5-qtdeclarative packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Bootstrap-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Bootstrap-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGLExtensions-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGLExtensions-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformHeaders-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtQuick5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtQuick5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtQuick5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtQuick5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-common-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtdeclarative-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtdeclarative-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtdeclarative-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtdeclarative-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtdeclarative-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtdeclarative-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtdeclarative-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtdeclarative-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtdeclarative-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtdeclarative-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libQt5Bootstrap-devel-static-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Concurrent-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Concurrent5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Concurrent5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Core-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Core-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Core5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Core5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5DBus-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5DBus-devel-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5DBus-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5DBus5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5DBus5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Gui-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Gui-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Gui5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Gui5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Network-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Network-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Network5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Network5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5OpenGL-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5OpenGL-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5OpenGL5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5OpenGL5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5OpenGLExtensions-devel-static-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5PlatformHeaders-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5PlatformSupport-devel-static-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5PlatformSupport-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5PrintSupport-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5PrintSupport-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5PrintSupport5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5PrintSupport5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql5-mysql-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql5-mysql-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql5-postgresql-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql5-postgresql-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql5-sqlite-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql5-sqlite-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql5-unixODBC-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Sql5-unixODBC-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Test-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Test-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Test5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Test5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Widgets-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Widgets-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Widgets5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Widgets5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Xml-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Xml5-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQt5Xml5-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQtQuick5-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libQtQuick5-debuginfo-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtbase-common-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtbase-common-devel-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtbase-debugsource-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtbase-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtbase-examples-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtbase-examples-debuginfo-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtbase-private-headers-devel-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtdeclarative-debugsource-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtdeclarative-devel-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtdeclarative-devel-debuginfo-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtdeclarative-examples-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtdeclarative-examples-debuginfo-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtdeclarative-private-headers-devel-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtdeclarative-tools-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libqt5-qtdeclarative-tools-debuginfo-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Bootstrap-devel-static-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Concurrent-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Concurrent5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Concurrent5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Core-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Core5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Core5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5DBus-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5DBus-devel-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5DBus5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5DBus5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Gui-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Gui5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Gui5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Network-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Network5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Network5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5OpenGL-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5OpenGL5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5OpenGL5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5OpenGLExtensions-devel-static-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5PlatformSupport-devel-static-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5PrintSupport-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5PrintSupport5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5PrintSupport5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql5-mysql-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql5-mysql-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql5-postgresql-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql5-postgresql-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql5-sqlite-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql5-sqlite-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Test-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Test5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Test5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Widgets-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Widgets5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Widgets5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Xml-devel-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Xml5-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQt5Xml5-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQtQuick5-32bit-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libQtQuick5-debuginfo-32bit-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libqt5-qtbase-examples-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libqt5-qtbase-examples-debuginfo-32bit-5.6.1-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libqt5-qtdeclarative-devel-32bit-5.6.1-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libqt5-qtdeclarative-devel-debuginfo-32bit-5.6.1-7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libQt5Bootstrap-devel-static-32bit / libQt5Bootstrap-devel-static / etc");
}
