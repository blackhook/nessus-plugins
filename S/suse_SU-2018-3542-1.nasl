#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3542-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118499);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-9843", "CVE-2018-3133", "CVE-2018-3174", "CVE-2018-3282");

  script_name(english:"SUSE SLES11 Security Update : mysql (SUSE-SU-2018:3542-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MySQL server was updated to version 5.5.62, fixing bugs and security
issues.

Changes :

http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-62.html

Following security issues were fixed :

CVE-2016-9843: The crc32_big function in zlib might have allowed
context-dependent attackers to have unspecified impact via vectors
involving big-endian CRC calculation. (bsc#1013882) Please note that
SUSE uses the system zlib, not the embedded copy.

CVE-2018-3133: Authenticated low privilege attackers could cause
denial of service attacks (hangs or crashes) against the mysql server
(bsc#1112369)

CVE-2018-3174: Authenticated high privilege attackers could cause
denial of service attacks (hangs or crashes) against the mysql server
(bsc#1112368)

CVE-2018-3282: Authenticated high privilege attackers could cause
denial of service attacks (hangs or crashes) against the mysql server
(bsc#1112432)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-62.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-62.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9843/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3133/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3174/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3282/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183542-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a067b109"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-mysql-13849=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-mysql-13849=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-mysql-13849=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-mysql-13849=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-mysql-13849=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-mysql-13849=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/30");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client_r18-32bit-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client18-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client_r18-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-client-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-tools-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client18-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libmysql55client_r18-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-client-5.5.62-0.39.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mysql-tools-5.5.62-0.39.18.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql");
}
