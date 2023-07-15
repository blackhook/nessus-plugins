#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1902-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110966);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2016-10040");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libqt4 (SUSE-SU-2018:1902-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libqt4 fixes the following issues: LibQt4 was updated
to 4.8.7 (bsc#1039291, CVE-2016-10040): See
http://download.qt.io/official_releases/qt/4.8/4.8.7/changes-4.8.7 for
more details. Also libQtWebkit4 was updated to 2.3.4 to match libqt4.
Also following bugs were fixed :

  - Enable libqt4-devel-32bit (bsc#982826)

  - Fixed bolder font in Qt4 apps (boo#956357)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.qt.io/official_releases/qt/4.8/4.8.7/changes-4.8.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1042657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10040/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181902-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95907001"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2018-1288=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-1288=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-1288=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-1288=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQtWebKit4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQtWebKit4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQtWebKit4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqca2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqca2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqca2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-devel-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-devel-doc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-qt3support-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qt4-qtscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qt4-qtscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qt4-qtscript-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qt4-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qt4-x11-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libQtWebKit4-debuginfo-32bit-4.8.7+2.3.4-4.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libQtWebKit4-debuginfo-4.8.7+2.3.4-4.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"libQtWebKit4-debugsource-4.8.7+2.3.4-4.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libQtWebKit4-32bit-4.8.7+2.3.4-4.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libQtWebKit4-4.8.7+2.3.4-4.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqca2-2.0.3-17.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqca2-32bit-2.0.3-17.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqca2-debuginfo-2.0.3-17.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqca2-debuginfo-32bit-2.0.3-17.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqca2-debugsource-2.0.3-17.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-debugsource-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-devel-doc-debuginfo-4.8.7-8.6.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-devel-doc-debugsource-4.8.7-8.6.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-qt3support-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-qt3support-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-qt3support-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-qt3support-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-sql-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-sql-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-sql-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-sql-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-sql-mysql-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-sql-mysql-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-sql-plugins-debugsource-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-sql-sqlite-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-sql-sqlite-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-x11-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-x11-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-x11-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqt4-x11-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qt4-x11-tools-4.8.7-8.6.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qt4-x11-tools-debuginfo-4.8.7-8.6.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libQtWebKit4-32bit-4.8.7+2.3.4-4.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libQtWebKit4-4.8.7+2.3.4-4.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libQtWebKit4-debuginfo-32bit-4.8.7+2.3.4-4.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libQtWebKit4-debuginfo-4.8.7+2.3.4-4.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libQtWebKit4-debugsource-4.8.7+2.3.4-4.5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqca2-2.0.3-17.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqca2-32bit-2.0.3-17.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqca2-debuginfo-2.0.3-17.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqca2-debuginfo-32bit-2.0.3-17.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqca2-debugsource-2.0.3-17.2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-debugsource-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-qt3support-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-qt3support-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-qt3support-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-qt3support-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-mysql-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-mysql-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-mysql-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-mysql-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-plugins-debugsource-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-postgresql-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-postgresql-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-postgresql-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-postgresql-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-sqlite-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-sqlite-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-sqlite-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-sqlite-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-unixODBC-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-unixODBC-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-unixODBC-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-sql-unixODBC-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-x11-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-x11-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-x11-debuginfo-32bit-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqt4-x11-debuginfo-4.8.7-8.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qt4-qtscript-0.2.0-11.2.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qt4-qtscript-debuginfo-0.2.0-11.2.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qt4-qtscript-debugsource-0.2.0-11.2.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt4");
}
