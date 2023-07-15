#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-726.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111097);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10040");

  script_name(english:"openSUSE Security Update : libqt4 (openSUSE-2018-726)");
  script_summary(english:"Check for the openSUSE-2018-726 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libqt4 fixes the following issues :

LibQt4 was updated to 4.8.7 (bsc#1039291, CVE-2016-10040) :

See
&#9;http://download.qt.io/official_releases/qt/4.8/4.8.7/changes-4.8.7
for more details.

Also libQtWebkit4 was updated to 2.3.4 to match libqt4.

Also following bugs were fixed :

  - Enable libqt4-devel-32bit (bsc#982826)

  - Fixed bolder font in Qt4 apps (boo#956357)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.qt.io/official_releases/qt/4.8/4.8.7/changes-4.8.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982826"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libqt4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtWebKit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtWebKit4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtWebKit4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtWebKit4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtWebKit4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtWebKit4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-plugin-cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-plugin-cyrus-sasl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-plugin-cyrus-sasl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-plugin-cyrus-sasl-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-plugin-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-plugin-pkcs11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-plugin-pkcs11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqca2-plugin-pkcs11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-linguist-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-qtscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-qtscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-qtscript-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-x11-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/16");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libQtWebKit-devel-4.8.7+2.3.4-7.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libQtWebKit4-4.8.7+2.3.4-7.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libQtWebKit4-debuginfo-4.8.7+2.3.4-7.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libQtWebKit4-debugsource-4.8.7+2.3.4-7.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqca2-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqca2-debuginfo-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqca2-debugsource-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqca2-devel-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqca2-devel-debuginfo-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqca2-plugin-cyrus-sasl-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqca2-plugin-cyrus-sasl-debuginfo-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqca2-plugin-pkcs11-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqca2-plugin-pkcs11-debuginfo-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-debuginfo-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-debugsource-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-devel-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-devel-debuginfo-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-devel-doc-data-4.8.7-17.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-devel-doc-debuginfo-4.8.7-17.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-devel-doc-debugsource-4.8.7-17.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-linguist-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-linguist-debuginfo-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-private-headers-devel-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-qt3support-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-qt3support-debuginfo-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-debuginfo-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-mysql-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-mysql-debuginfo-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-plugins-debugsource-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-postgresql-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-postgresql-debuginfo-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-sqlite-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-sqlite-debuginfo-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-unixODBC-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-sql-unixODBC-debuginfo-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-x11-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqt4-x11-debuginfo-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qt4-qtscript-0.2.0-15.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qt4-qtscript-debuginfo-0.2.0-15.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qt4-qtscript-debugsource-0.2.0-15.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qt4-x11-tools-4.8.7-17.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qt4-x11-tools-debuginfo-4.8.7-17.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libQtWebKit4-32bit-4.8.7+2.3.4-7.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libQtWebKit4-debuginfo-32bit-4.8.7+2.3.4-7.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqca2-32bit-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqca2-debuginfo-32bit-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqca2-plugin-cyrus-sasl-32bit-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqca2-plugin-cyrus-sasl-debuginfo-32bit-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqca2-plugin-pkcs11-32bit-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqca2-plugin-pkcs11-debuginfo-32bit-2.0.3-22.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-debuginfo-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-devel-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-devel-debuginfo-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-qt3support-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-qt3support-debuginfo-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-sql-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-sql-debuginfo-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-sql-mysql-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-sql-mysql-debuginfo-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-sql-postgresql-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-sql-postgresql-debuginfo-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-sql-sqlite-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-sql-sqlite-debuginfo-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-sql-unixODBC-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-sql-unixODBC-debuginfo-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-x11-32bit-4.8.7-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libqt4-x11-debuginfo-32bit-4.8.7-17.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libQtWebKit-devel / libQtWebKit4-32bit / libQtWebKit4 / etc");
}
