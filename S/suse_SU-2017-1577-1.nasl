#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1577-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100865);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libqt5-qtbase, libqt5-qtdeclarative (SUSE-SU-2017:1577-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libqt5-qtbase and libqt5-qtdeclarative fixes the
following issues: This security issue was fixed :

  - Prevent potential information leak due to race condition
    in QSaveFile (bsc#1034005).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034402"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171577-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c7ac7d7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-967=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-967=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-967=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-967=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Concurrent5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Core5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5DBus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5DBus5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Gui5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Network5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5OpenGL5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5OpenGL5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5PrintSupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5PrintSupport5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Test5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Widgets5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Xml5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQtQuick5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQtQuick5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtbase-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtdeclarative-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Concurrent5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Concurrent5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Core5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Core5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5DBus5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5DBus5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Gui5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Gui5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Network5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Network5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5OpenGL5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5OpenGL5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5PrintSupport5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5PrintSupport5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-mysql-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-mysql-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-postgresql-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-postgresql-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-sqlite-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-sqlite-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Test5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Test5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Widgets5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Widgets5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Xml5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQt5Xml5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQtQuick5-5.6.1-13.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libQtQuick5-debuginfo-5.6.1-13.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libqt5-qtbase-debugsource-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libqt5-qtdeclarative-debugsource-5.6.1-13.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Concurrent5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Concurrent5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Core5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Core5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5DBus5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5DBus5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Gui5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Gui5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Network5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Network5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5OpenGL5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5OpenGL5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5PrintSupport5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5PrintSupport5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-mysql-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-mysql-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-postgresql-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-postgresql-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-sqlite-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-sqlite-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Test5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Test5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Widgets5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Widgets5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Xml5-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQt5Xml5-debuginfo-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQtQuick5-5.6.1-13.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libQtQuick5-debuginfo-5.6.1-13.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libqt5-qtbase-debugsource-5.6.1-17.3.15")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libqt5-qtdeclarative-debugsource-5.6.1-13.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt5-qtbase / libqt5-qtdeclarative");
}
