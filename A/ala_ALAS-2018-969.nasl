#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-969.
#

include("compat.inc");

if (description)
{
  script_id(107240);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2018-2565", "CVE-2018-2573", "CVE-2018-2576", "CVE-2018-2583", "CVE-2018-2586", "CVE-2018-2590", "CVE-2018-2600", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2645", "CVE-2018-2646", "CVE-2018-2647", "CVE-2018-2665", "CVE-2018-2667", "CVE-2018-2668", "CVE-2018-2696", "CVE-2018-2703");
  script_xref(name:"ALAS", value:"2018-969");

  script_name(english:"Amazon Linux AMI : mysql55 / mysql56,mysql57 (ALAS-2018-969)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.5.58 and prior, 5.6.38 and prior and 5.7.20 and prior.
Easily exploitable vulnerability allows low privileged attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of MySQL Server. (CVE-2018-2640)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: GIS). Supported versions that are affected are
5.6.38 and prior and 5.7.20 and prior. Easily exploitable
vulnerability allows low privileged attacker with network access via
multiple protocols to compromise MySQL Server. Successful attacks of
this vulnerability can result in unauthorized ability to cause a hang
or frequently repeatable crash (complete DOS) of MySQL Server.
(CVE-2018-2573)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Replication). Supported versions that are
affected are 5.6.38 and prior and 5.7.20 and prior. Easily exploitable
vulnerability allows high privileged attacker with network access via
multiple protocols to compromise MySQL Server. Successful attacks of
this vulnerability can result in unauthorized ability to cause a hang
or frequently repeatable crash (complete DOS) of MySQL Server as well
as unauthorized update, insert or delete access to some of MySQL
Server accessible data. (CVE-2018-2647)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DML). Supported versions that are affected are
5.7.20 and prior. Easily exploitable vulnerability allows high
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. (CVE-2018-2576)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.5.58 and prior, 5.6.38 and prior and 5.7.20 and prior.
Easily exploitable vulnerability allows low privileged attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of MySQL Server. (CVE-2018-2668)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: InnoDB). Supported versions that are affected
are 5.7.20 and prior. Easily exploitable vulnerability allows high
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVE-2018-2565)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DML). Supported versions that are affected are
5.7.20 and prior. Easily exploitable vulnerability allows high
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. (CVE-2018-2586)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: InnoDB). Supported versions that are affected are
5.6.38 and prior and 5.7.20 and prior. Easily exploitable
vulnerability allows high privileged attacker with network access via
multiple protocols to compromise MySQL Server. Successful attacks of
this vulnerability can result in unauthorized creation, deletion or
modification access to critical data or all MySQL Server accessible
data and unauthorized ability to cause a hang or frequently repeatable
crash (complete DOS) of MySQL Server. (CVE-2018-2612)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server : Security : Privileges). Supported versions
that are affected are 5.6.38 and prior and 5.7.20 and prior. Easily
exploitable vulnerability allows unauthenticated attacker with network
access via multiple protocols to compromise MySQL Server. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of MySQL
Server. (CVE-2018-2696)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Stored Procedure). Supported versions that are affected
are 5.6.38 and prior and 5.7.20 and prior. Easily exploitable
vulnerability allows high privileged attacker with network access via
multiple protocols to compromise MySQL Server. While the vulnerability
is in MySQL Server, attacks may significantly impact additional
products. Successful attacks of this vulnerability can result in
unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of MySQL Server. (CVE-2018-2583)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DDL). Supported versions that are affected are
5.5.58 and prior, 5.6.38 and prior and 5.7.20 and prior. Easily
exploitable vulnerability allows low privileged attacker with network
access via multiple protocols to compromise MySQL Server. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of MySQL
Server. (CVE-2018-2622)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.7.20 and prior. Easily exploitable vulnerability allows
high privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. (CVE-2018-2600)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Performance Schema). Supported versions that
are affected are 5.6.38 and prior and 5.7.20 and prior. Easily
exploitable vulnerability allows high privileged attacker with network
access via multiple protocols to compromise MySQL Server. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of MySQL
Server. (CVE-2018-2590)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Performance Schema). Supported versions that
are affected are 5.6.38 and prior and 5.7.20 and prior. Easily
exploitable vulnerability allows high privileged attacker with network
access via multiple protocols to compromise MySQL Server. Successful
attacks of this vulnerability can result in unauthorized access to
critical data or complete access to all MySQL Server accessible data.
(CVE-2018-2645)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server : Security : Privileges). Supported versions
that are affected are 5.6.38 and prior and 5.7.20 and prior. Easily
exploitable vulnerability allows low privileged attacker with network
access via multiple protocols to compromise MySQL Server. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of MySQL
Server. (CVE-2018-2703)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DML). Supported versions that are affected are
5.7.20 and prior. Easily exploitable vulnerability allows high
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. (CVE-2018-2646)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.5.58 and prior, 5.6.38 and prior and 5.7.20 and prior.
Easily exploitable vulnerability allows low privileged attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of MySQL Server. (CVE-2018-2665)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Supported versions that are
affected are 5.7.20 and prior. Easily exploitable vulnerability allows
high privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. (CVE-2018-2667)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-969.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update mysql55' to update your system.

Run 'yum update mysql56' to update your system.

Run 'yum update mysql57' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql56-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql57-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql57-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql57-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql57-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql57-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql57-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql57-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql57-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/09");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"mysql-config-5.5.59-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-5.5.59-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-bench-5.5.59-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-debuginfo-5.5.59-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-devel-5.5.59-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-embedded-5.5.59-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-embedded-devel-5.5.59-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-libs-5.5.59-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-server-5.5.59-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-test-5.5.59-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-bench-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-common-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-debuginfo-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-devel-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-devel-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-errmsg-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-libs-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-server-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-test-5.6.39-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-5.7.21-2.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-common-5.7.21-2.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-debuginfo-5.7.21-2.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-devel-5.7.21-2.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-embedded-5.7.21-2.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-embedded-devel-5.7.21-2.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-errmsg-5.7.21-2.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-libs-5.7.21-2.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-server-5.7.21-2.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-test-5.7.21-2.6.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-config / mysql55 / mysql55-bench / mysql55-debuginfo / etc");
}
