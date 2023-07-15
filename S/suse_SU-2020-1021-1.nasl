#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1021-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(135753);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19873");

  script_name(english:"SUSE SLES12 Security Update : libqt4 (SUSE-SU-2020:1021-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libqt4 fixes the following issues :

CVE-2018-15518: Fixed a double free in QXmlStreamReader (bsc#1118595)

CVE-2018-19873: Fixed a segmantation fault via a malformed BMP file
(bsc#1118596).

CVE-2018-19869: Fixed an improper checking which might lead to a crach
via a malformed url reference (bsc#1118599).

Added stricter toplevel asm parsing by dropping volatile qualification
that has no effect (bsc#1121214).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15518/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19869/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19873/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201021-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7eaaa4b3"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP5:zypper in -t patch
SUSE-SLE-WE-12-SP5-2020-1021=1

SUSE Linux Enterprise Workstation Extension 12-SP4:zypper in -t patch
SUSE-SLE-WE-12-SP4-2020-1021=1

SUSE Linux Enterprise Software Development Kit 12-SP5:zypper in -t
patch SUSE-SLE-SDK-12-SP5-2020-1021=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2020-1021=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2020-1021=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2020-1021=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-sql-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt4-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qt4-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qt4-x11-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-debuginfo-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-debugsource-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-devel-doc-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-devel-doc-debugsource-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-qt3support-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-qt3support-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-qt3support-debuginfo-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-qt3support-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-sql-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-sql-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-sql-debuginfo-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-sql-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-sql-mysql-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-sql-mysql-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-sql-plugins-debugsource-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-sql-sqlite-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-sql-sqlite-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-x11-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-x11-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-x11-debuginfo-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libqt4-x11-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qt4-x11-tools-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qt4-x11-tools-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-debuginfo-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-debugsource-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-devel-doc-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-devel-doc-debugsource-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-qt3support-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-qt3support-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-qt3support-debuginfo-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-qt3support-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-sql-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-sql-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-sql-debuginfo-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-sql-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-sql-mysql-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-sql-mysql-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-sql-plugins-debugsource-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-sql-sqlite-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-sql-sqlite-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-x11-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-x11-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-x11-debuginfo-32bit-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libqt4-x11-debuginfo-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"qt4-x11-tools-4.8.7-8.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"qt4-x11-tools-debuginfo-4.8.7-8.13.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt4");
}
