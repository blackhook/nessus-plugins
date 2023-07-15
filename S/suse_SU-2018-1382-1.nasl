#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1382-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110089);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819");

  script_name(english:"SUSE SLES12 Security Update : mariadb (SUSE-SU-2018:1382-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"MariaDB was updated to 10.0.35 (bsc#1090518) Notable changes :

  - PCRE updated to 8.42

  - XtraDB updated to 5.6.39-83.1

  - TokuDB updated to 5.6.39-83.1

  - InnoDB updated to 5.6.40

  - The embedded server library now supports SSL when
    connecting to remote servers [bsc#1088681],
    [CVE-2018-2767]

  - MDEV-15249 - Crash in MVCC read after IMPORT TABLESPACE

  - MDEV-14988 - innodb_read_only tries to modify files if
    transactions were recovered in COMMITTED state

  - MDEV-14773 - DROP TABLE hangs for InnoDB table with
    FULLTEXT index

  - MDEV-15723 - Crash in
    INFORMATION_SCHEMA.INNODB_SYS_TABLES when accessing
    corrupted record

  - fixes for the following security vulnerabilities:
    CVE-2018-2782, CVE-2018-2784, CVE-2018-2787,
    CVE-2018-2766, CVE-2018-2755, CVE-2018-2819,
    CVE-2018-2817, CVE-2018-2761, CVE-2018-2781,
    CVE-2018-2771, CVE-2018-2813

  - Release notes and changelog :

    - https://kb.askmonty.org/en/mariadb-10035-release-notes

    - https://kb.askmonty.org/en/mariadb-10035-changelog

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090518"
  );
  # https://kb.askmonty.org/en/mariadb-10035-changelog
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10035-changelog/"
  );
  # https://kb.askmonty.org/en/mariadb-10035-release-notes
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10035-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2755/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2761/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2766/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2767/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2771/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2781/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2782/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2784/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2787/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2813/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2817/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2819/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181382-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36a87777"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-966=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient-devel-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-32bit-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-debuginfo-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-debuginfo-32bit-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient_r18-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqld-devel-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqld18-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqld18-debuginfo-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-client-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-client-debuginfo-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-debuginfo-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-debugsource-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-errormessages-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-tools-10.0.35-20.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-tools-debuginfo-10.0.35-20.46.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
