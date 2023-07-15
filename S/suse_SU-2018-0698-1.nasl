#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0698-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(108402);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2018-2562", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668");

  script_name(english:"SUSE SLES12 Security Update : mariadb (SUSE-SU-2018:0698-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mariadb to 10.0.34 fixes several issues. These
security issues were fixed :

  - CVE-2017-10378: Vulnerability in subcomponent: Server:
    Optimizer. Easily exploitable vulnerability allowed low
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) (bsc#1064115).

  - CVE-2017-10268: Vulnerability in subcomponent: Server:
    Replication. Difficult to exploit vulnerability allowed
    high privileged attacker with logon to the
    infrastructure where MySQL Server executes to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized access to critical data or
    complete access to all MySQL Server accessible data
    (bsc#1064101).

  - CVE-2018-2562: Vulnerability in the MySQL Server
    subcomponent: Server : Partition. Easily exploitable
    vulnerability allowed low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server as well as unauthorized update, insert or delete
    access to some of MySQL Server accessible data.

  - CVE-2018-2622: Vulnerability in the MySQL Server
    subcomponent: Server: DDL. Easily exploitable
    vulnerability allowed low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.

  - CVE-2018-2640: Vulnerability in the MySQL Server
    subcomponent: Server: Optimizer. Successful attacks of
    this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server.

  - CVE-2018-2665: Vulnerability in the MySQL Server
    subcomponent: Server: Optimizer. Easily exploitable
    vulnerability allowed low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.

  - CVE-2018-2668: Vulnerability in the MySQL Server
    subcomponent: Server: Optimizer. Easily exploitable
    vulnerability allowed low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server.

  - CVE-2018-2612: Vulnerability in the MySQL Server
    subcomponent: InnoDB. Easily exploitable vulnerability
    allowed high privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access
    to critical data or all MySQL Server accessible data and
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server.

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10268/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10378/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2562/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2612/"
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
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180698-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12e95d3a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-477=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/16");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient-devel-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-32bit-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-debuginfo-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-debuginfo-32bit-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient_r18-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqld-devel-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqld18-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqld18-debuginfo-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-client-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-client-debuginfo-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-debuginfo-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-debugsource-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-errormessages-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-tools-10.0.34-20.43.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-tools-debuginfo-10.0.34-20.43.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
