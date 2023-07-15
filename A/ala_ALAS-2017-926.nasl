#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-926.
#

include("compat.inc");

if (description)
{
  script_id(105050);
  script_version("3.4");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-10155", "CVE-2017-10227", "CVE-2017-10268", "CVE-2017-10276", "CVE-2017-10279", "CVE-2017-10283", "CVE-2017-10286", "CVE-2017-10294", "CVE-2017-10314", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384");
  script_xref(name:"ALAS", value:"2017-926");

  script_name(english:"Amazon Linux AMI : mysql56 / mysql57 (ALAS-2017-926)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Client programs). Easily exploitable vulnerability
allows low privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized access to critical data or
complete access to all MySQL Server accessible data. (CVE-2017-10379)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Easily exploitable vulnerability
allows low privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL Server.
(CVE-2017-10378)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Performance Schema). Difficult to exploit
vulnerability allows low privileged attacker with network access via
multiple protocols to compromise MySQL Server. Successful attacks of
this vulnerability can result in unauthorized ability to cause a hang
or frequently repeatable crash (complete DOS) of MySQL Server.
(CVE-2017-10283)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Easily exploitable vulnerability
allows high privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL Server.
(CVE-2017-10227)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Easily exploitable vulnerability
allows high privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL
Server.(CVE-2017-10294)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Replication). Difficult to exploit
vulnerability allows high privileged attacker with logon to the
infrastructure where MySQL Server executes to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
access to critical data or complete access to all MySQL Server
accessible data. (CVE-2017-10268)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Pluggable Auth). Easily exploitable
vulnerability allows unauthenticated attacker with network access via
multiple protocols to compromise MySQL Server. Successful attacks of
this vulnerability can result in unauthorized ability to cause a hang
or frequently repeatable crash (complete DOS) of MySQL
Server.(CVE-2017-10155)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Memcached). Easily exploitable vulnerability
allows high privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL
Server.(CVE-2017-10314)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DDL). Easily exploitable vulnerability allows
low privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server.(CVE-2017-10384)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: FTS). Easily exploitable vulnerability allows
low privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. (CVE-2017-10276)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: InnoDB). Difficult to exploit vulnerability
allows high privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL
Server.(CVE-2017-10286)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Easily exploitable vulnerability
allows high privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL
Server.(CVE-2017-10279)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-926.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update mysql56' to update your system.

Run 'yum update mysql57' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"mysql56-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-bench-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-common-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-debuginfo-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-devel-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-devel-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-errmsg-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-libs-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-server-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-test-5.6.38-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-5.7.20-2.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-common-5.7.20-2.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-debuginfo-5.7.20-2.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-devel-5.7.20-2.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-embedded-5.7.20-2.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-embedded-devel-5.7.20-2.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-errmsg-5.7.20-2.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-libs-5.7.20-2.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-server-5.7.20-2.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-test-5.7.20-2.5.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql56 / mysql56-bench / mysql56-common / mysql56-debuginfo / etc");
}
