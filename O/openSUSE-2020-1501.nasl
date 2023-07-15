#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1501.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140743);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id("CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19873", "CVE-2020-17507");

  script_name(english:"openSUSE Security Update : libqt4 (openSUSE-2020-1501)");
  script_summary(english:"Check for the openSUSE-2020-1501 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libqt4 fixes the following issues :

  - Fix buffer over-read in read_xbm_body (boo#1176315,
    CVE-2020-17507)

  - Fix 'double free or corruption' in QXmlStreamReader
    (boo#1118595, CVE-2018-15518)

  - Fix QBmpHandler segfault on malformed BMP file
    boo#1118596, CVE-2018-19873)

  - Fix crash when parsing malformed url reference
    (boo#1118599, CVE-2018-19869)

This update was imported from the openSUSE:Leap:15.1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176315"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libqt4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-devel-doc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-linguist-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-qt3support-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-sql-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt4-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qt4-x11-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/23");
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

if ( rpm_check(release:"SUSE15.2", reference:"libqt4-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-debugsource-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-devel-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-devel-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-devel-doc-data-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-linguist-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-linguist-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-private-headers-devel-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-qt3support-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-qt3support-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-sql-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-sql-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-sql-sqlite-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-sql-sqlite-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-x11-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libqt4-x11-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-32bit-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-32bit-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-devel-32bit-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-devel-32bit-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-devel-doc-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-devel-doc-debugsource-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-qt3support-32bit-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-qt3support-32bit-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-sql-32bit-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-sql-32bit-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-sql-plugins-debugsource-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-sql-postgresql-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-sql-postgresql-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-sql-sqlite-32bit-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-sql-sqlite-32bit-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-sql-unixODBC-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-sql-unixODBC-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-x11-32bit-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libqt4-x11-32bit-debuginfo-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"qt4-x11-tools-4.8.7-lp152.10.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"qt4-x11-tools-debuginfo-4.8.7-lp152.10.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt4-devel-doc-data / libqt4-devel-doc-debuginfo / etc");
}
