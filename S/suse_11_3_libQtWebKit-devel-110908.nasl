#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libQtWebKit-devel-5125.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75609);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-3193", "CVE-2011-3194");

  script_name(english:"openSUSE Security Update : libQtWebKit-devel (openSUSE-SU-2011:1119-1)");
  script_summary(english:"Check for the libQtWebKit-devel-5125 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted font files could cause a single byte heap based
buffer overflow (CVE-2011-3193).

Specially crafted grey scale images could cause a heap based buffer
overflow (CVE-2011-3194).

The update also fixes the following non-security bugs :

  - fix QFileDialog not showing system files (bnc#669604)

  - fix font fallback handling (bnc#643848)

  - add support for postgresql 8.3 and 9 (bnc#668210)

  - Path added: bnc#592962 - Set application icon."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=592962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=643848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2011-10/msg00007.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libQtWebKit-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtWebKit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtWebKit4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQtWebKit4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-x11-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"libQtWebKit-devel-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libQtWebKit4-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libqt4-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libqt4-devel-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libqt4-devel-doc-data-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libqt4-qt3support-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libqt4-sql-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libqt4-sql-mysql-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libqt4-sql-postgresql-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libqt4-sql-sqlite-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libqt4-sql-unixODBC-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libqt4-x11-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"qt4-x11-tools-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libQtWebKit4-32bit-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libqt4-32bit-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libqt4-qt3support-32bit-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libqt4-sql-32bit-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libqt4-sql-mysql-32bit-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libqt4-sql-postgresql-32bit-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libqt4-sql-sqlite-32bit-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libqt4-sql-unixODBC-32bit-4.6.3-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libqt4-x11-32bit-4.6.3-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libQtWebKit-devel / libQtWebKit4 / libQtWebKit4-32bit / libqt4 / etc");
}
