#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1078.
#

include("compat.inc");

if (description)
{
  script_id(117592);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384", "CVE-2017-3636", "CVE-2017-3641", "CVE-2017-3651", "CVE-2017-3653", "CVE-2018-2562", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819");
  script_xref(name:"ALAS", value:"2018-1078");

  script_name(english:"Amazon Linux 2 : mariadb (ALAS-2018-1078)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.5.57 and earlier. Easily exploitable vulnerability
allows low privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0
Base Score 6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2017-10378 )

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.5.59 and prior. Easily exploitable vulnerability allows
high privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
4.9 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-2781)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server : Partition). Supported versions that are
affected are 5.5.58 and prior. Easily exploitable vulnerability allows
low privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server as well as
unauthorized update, insert or delete access to some of MySQL Server
accessible data. CVSS 3.0 Base Score 7.1 (Integrity and Availability
impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H).(CVE-2018-2562)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Client mysqldump). Supported versions that are affected
are 5.5.56 and earlier. Easily exploitable vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized update, insert or delete access to some of
MySQL Server accessible data. CVSS 3.0 Base Score 4.3 (Integrity
impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N).(CVE-2017-3651)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Replication). Supported versions that are
affected are 5.5.59 and prior. Difficult to exploit vulnerability
allows unauthenticated attacker with logon to the infrastructure where
MySQL Server executes to compromise MySQL Server. Successful attacks
require human interaction from a person other than the attacker and
while the vulnerability is in MySQL Server, attacks may significantly
impact additional products. Successful attacks of this vulnerability
can result in takeover of MySQL Server. CVSS 3.0 Base Score 7.7
(Confidentiality, Integrity and Availability impacts). CVSS Vector:
(CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).(CVE-2018-2755)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.5.58 and prior. Easily exploitable vulnerability allows
low privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-2640)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Client programs). Supported versions that are affected
are 5.5.57 and earlier. Easily exploitable vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized access to critical data or complete access to
all MySQL Server accessible data. CVSS 3.0 Base Score 6.5
(Confidentiality impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N).(CVE-2017-10379 )

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Replication). Supported versions that are
affected are 5.5.57 and earlier. Difficult to exploit vulnerability
allows high privileged attacker with logon to the infrastructure where
MySQL Server executes to compromise MySQL Server. Successful attacks
of this vulnerability can result in unauthorized access to critical
data or complete access to all MySQL Server accessible data. CVSS 3.0
Base Score 4.1 (Confidentiality impacts). CVSS Vector:
(CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N).(CVE-2017-10268)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DDL). Supported versions that are affected are
5.5.56 and earlier. Difficult to exploit vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized update, insert or delete access to some of
MySQL Server accessible data. CVSS 3.0 Base Score 3.1 (Integrity
impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N).(CVE-2017-3653)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Locking). Supported versions that are affected
are 5.5.59 and prior. Difficult to exploit vulnerability allows high
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
4.4 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-2771)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Security: Encryption). Supported versions that
are affected are 5.5.59 and prior. Difficult to exploit vulnerability
allows low privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized read access to a subset of
MySQL Server accessible data. CVSS 3.0 Base Score 3.1 (Confidentiality
impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N).(CVE-2018-2767)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DDL). Supported versions that are affected are
5.5.59 and prior. Easily exploitable vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-2817)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.5.58 and prior, 5.6.38 and prior and 5.7.20 and prior.
Easily exploitable vulnerability allows low privileged attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of MySQL Server. CVSS 3.0 Base Score 6.5 (Availability impacts). CVSS
Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-2668)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DDL). Supported versions that are affected are
5.5.57 and earlier. Easily exploitable vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2017-10384)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DML). Supported versions that are affected are
5.5.56 and earlier. Easily exploitable vulnerability allows high
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
4.9 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).(CVE-2017-3641)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: InnoDB). Supported versions that are affected are
5.5.59 and prior. Easily exploitable vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-2819)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.5.58 and prior. Easily exploitable vulnerability allows
low privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-2665)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DDL). Supported versions that are affected are
5.5.58 and prior. Easily exploitable vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-2622)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DDL). Supported versions that are affected are
5.5.59 and prior. Easily exploitable vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized read access to a subset of MySQL Server
accessible data. CVSS 3.0 Base Score 4.3 (Confidentiality impacts).
CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).(CVE-2018-2813)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Client programs). Supported versions that are affected
are 5.5.56 and earlier. Easily exploitable vulnerability allows low
privileged attacker with logon to the infrastructure where MySQL
Server executes to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized update, insert or delete
access to some of MySQL Server accessible data as well as unauthorized
read access to a subset of MySQL Server accessible data and
unauthorized ability to cause a partial denial of service (partial
DOS) of MySQL Server. CVSS 3.0 Base Score 5.3 (Confidentiality,
Integrity and Availability impacts). CVSS Vector:
(CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L).(CVE-2017-3636)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Client programs). Supported versions that are affected
are 5.5.59 and prior. Difficult to exploit vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
5.9 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-2761)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1078.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mariadb' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"mariadb-5.5.60-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-bench-5.5.60-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-debuginfo-5.5.60-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-devel-5.5.60-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-embedded-5.5.60-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-embedded-devel-5.5.60-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-libs-5.5.60-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-server-5.5.60-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-test-5.5.60-1.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb / mariadb-bench / mariadb-debuginfo / mariadb-devel / etc");
}
