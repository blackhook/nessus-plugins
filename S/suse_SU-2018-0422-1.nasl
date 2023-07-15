#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0422-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106786);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-2562", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668");

  script_name(english:"SUSE SLES11 Security Update : mysql (SUSE-SU-2018:0422-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mysql to version 5.5.59 fixes several issues. These
security issues were fixed :

  - CVE-2018-2622: Vulnerability in the subcomponent:
    Server: DDL. Easily exploitable vulnerability allowed
    low privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server (bsc#1076369)

  - CVE-2018-2562: Vulnerability in the subcomponent: Server
    : Partition. Easily exploitable vulnerability allowed
    low privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update,
    insert or delete access to some of MySQL Server
    accessible data (bsc#1076369)

  - CVE-2018-2640: Vulnerability in the subcomponent:
    Server: Optimizer. Easily exploitable vulnerability
    allowed low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server
    (bsc#1076369)

  - CVE-2018-2665: Vulnerability in the subcomponent:
    Server: Optimizer. Easily exploitable vulnerability
    allowed low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server
    (bsc#1076369)

  - CVE-2018-2668: Vulnerability in the subcomponent:
    Server: Optimizer. Easily exploitable vulnerability
    allowed low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server
    (bsc#1076369) For additional changes please see
    http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-
    59.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-59.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-59.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2562/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2622/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2640/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2665/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2668/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180422-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aed9a615"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-mysql-13462=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-mysql-13462=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-mysql-13462=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/13");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.59-0.39.9.8")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.59-0.39.9.8")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.59-0.39.9.8")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client_r18-32bit-5.5.59-0.39.9.8")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client18-5.5.59-0.39.9.8")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client_r18-5.5.59-0.39.9.8")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-5.5.59-0.39.9.8")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-client-5.5.59-0.39.9.8")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-tools-5.5.59-0.39.9.8")) flag++;


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
