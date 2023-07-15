#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1564.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141080);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/05");

  script_cve_id("CVE-2020-17507");

  script_name(english:"openSUSE Security Update : libqt5-qtbase (openSUSE-2020-1564)");
  script_summary(english:"Check for the openSUSE-2020-1564 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libqt5-qtbase fixes the following issues :

  - CVE-2020-17507: Fixed a buffer overflow in XBM parser
    (bsc#1176315)

  - Fixed various issues discovered by fuzzing :

  - Made handling of XDG_RUNTIME_DIR more secure
    (bsc#1172515) :

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176315"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libqt5-qtbase packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Bootstrap-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Bootstrap-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5KmsSupport-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5KmsSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-common-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-platformtheme-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-platformtheme-gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-platformtheme-xdgdesktopportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-platformtheme-xdgdesktopportal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/30");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libQt5Bootstrap-devel-static-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Concurrent-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Concurrent5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Concurrent5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Core-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Core-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Core5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Core5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5DBus-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5DBus-devel-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5DBus-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5DBus5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5DBus5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Gui-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Gui-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Gui5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Gui5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5KmsSupport-devel-static-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5KmsSupport-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Network-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Network-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Network5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Network5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5OpenGL-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5OpenGL-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5OpenGL5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5OpenGL5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5OpenGLExtensions-devel-static-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5PlatformHeaders-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5PlatformSupport-devel-static-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5PlatformSupport-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5PrintSupport-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5PrintSupport-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5PrintSupport5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5PrintSupport5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql5-mysql-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql5-mysql-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql5-postgresql-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql5-postgresql-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql5-sqlite-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql5-sqlite-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql5-unixODBC-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Sql5-unixODBC-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Test-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Test-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Test5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Test5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Widgets-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Widgets-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Widgets5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Widgets5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Xml-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Xml5-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libQt5Xml5-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-common-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-common-devel-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-debugsource-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-examples-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-examples-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-platformtheme-gtk3-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-platformtheme-gtk3-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-platformtheme-xdgdesktopportal-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-platformtheme-xdgdesktopportal-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt5-qtbase-private-headers-devel-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Bootstrap-devel-static-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Concurrent-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Concurrent5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Concurrent5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Core-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Core5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Core5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5DBus-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5DBus-devel-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5DBus5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5DBus5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Gui-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Gui5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Gui5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Network-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Network5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Network5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5OpenGL-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5OpenGL5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5OpenGL5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5OpenGLExtensions-devel-static-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5PlatformSupport-devel-static-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5PrintSupport-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5PrintSupport5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5PrintSupport5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql5-mysql-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql5-mysql-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql5-postgresql-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql5-postgresql-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql5-sqlite-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql5-sqlite-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Test-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Test5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Test5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Widgets-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Widgets5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Widgets5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Xml-devel-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Xml5-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libQt5Xml5-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt5-qtbase-examples-32bit-5.12.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt5-qtbase-examples-32bit-debuginfo-5.12.7-lp152.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libQt5Bootstrap-devel-static / libQt5Concurrent-devel / etc");
}
