#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1333-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109938);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2771", "CVE-2018-2773", "CVE-2018-2781", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2818", "CVE-2018-2819");

  script_name(english:"SUSE SLES11 Security Update : mysql (SUSE-SU-2018:1333-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues :

  - Update to 5.5.60 in Oracle Apr2018 CPU (bsc#1089987).

  - CVE-2018-2761: Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Client
    programs). Supported versions that are affected are
    5.5.59 and prior, 5.6.39 and prior and 5.7.21 and prior.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS
    3.0 Base Score 5.9 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H).

  - CVE-2018-2755: Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server:
    Replication). Supported versions that are affected are
    5.5.59 and prior, 5.6.39 and prior and 5.7.21 and prior.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with logon to the
    infrastructure where MySQL Server executes to compromise
    MySQL Server. Successful attacks require human
    interaction from a person other than the attacker and
    while the vulnerability is in MySQL Server, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in takeover of
    MySQL Server. CVSS 3.0 Base Score 7.7 (Confidentiality,
    Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).

  - CVE-2018-2781: Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server:
    Optimizer). Supported versions that are affected are
    5.5.59 and prior, 5.6.39 and prior and 5.7.21 and prior.
    Easily exploitable vulnerability allows high privileged
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.0 Base Score 4.9
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

  - CVE-2018-2819: Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: InnoDB).
    Supported versions that are affected are 5.5.59 and
    prior, 5.6.39 and prior and 5.7.21 and prior. Easily
    exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 6.5 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).

  - CVE-2018-2818: Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server :
    Security : Privileges). Supported versions that are
    affected are 5.5.59 and prior, 5.6.39 and prior and
    5.7.21 and prior. Easily exploitable vulnerability
    allows high privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS
    3.0 Base Score 4.9 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

  - CVE-2018-2817: Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server: DDL).
    Supported versions that are affected are 5.5.59 and
    prior, 5.6.39 and prior and 5.7.21 and prior. Easily
    exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 6.5 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).

  - CVE-2018-2771: Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server:
    Locking). Supported versions that are affected are
    5.5.59 and prior, 5.6.39 and prior and 5.7.21 and prior.
    Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. CVSS 3.0 Base Score 4.4
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).

  - CVE-2018-2813: Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Server: DDL).
    Supported versions that are affected are 5.5.59 and
    prior, 5.6.39 and prior and 5.7.21 and prior. Easily
    exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized read access to a subset of
    MySQL Server accessible data. CVSS 3.0 Base Score 4.3
    (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).

  - CVE-2018-2773: Vulnerability in the MySQL Server
    component of Oracle MySQL (subcomponent: Client
    programs). Supported versions that are affected are
    5.5.59 and prior, 5.6.39 and prior and 5.7.21 and prior.
    Difficult to exploit vulnerability allows high
    privileged attacker with logon to the infrastructure
    where MySQL Server executes to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS
    3.0 Base Score 4.1 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089987"
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
    value:"https://www.suse.com/security/cve/CVE-2018-2771/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2773/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2781/"
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
    value:"https://www.suse.com/security/cve/CVE-2018-2818/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2819/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181333-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c08472b6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-mysql-13611=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-mysql-13611=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-mysql-13611=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysql55client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/21");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.60-0.39.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.60-0.39.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client18-32bit-5.5.60-0.39.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libmysql55client_r18-32bit-5.5.60-0.39.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client18-5.5.60-0.39.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libmysql55client_r18-5.5.60-0.39.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-5.5.60-0.39.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-client-5.5.60-0.39.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mysql-tools-5.5.60-0.39.12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql");
}
