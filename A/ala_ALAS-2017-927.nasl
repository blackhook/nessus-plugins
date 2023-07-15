#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-927.
#

include("compat.inc");

if (description)
{
  script_id(105051);
  script_version("3.3");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384");
  script_xref(name:"ALAS", value:"2017-927");

  script_name(english:"Amazon Linux AMI : mysql55 (ALAS-2017-927)");
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
complete access to all MySQL Server accessible data.(CVE-2017-10379)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Optimizer). Easily exploitable vulnerability
allows low privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL
Server.(CVE-2017-10378)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: DDL). Easily exploitable vulnerability allows
low privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server.(CVE-2017-10384)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Replication). Difficult to exploit
vulnerability allows high privileged attacker with logon to the
infrastructure where MySQL Server executes to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
access to critical data or complete access to all MySQL Server
accessible data.(CVE-2017-10268)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-927.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql55' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"mysql-config-5.5.58-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-5.5.58-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-bench-5.5.58-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-debuginfo-5.5.58-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-devel-5.5.58-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-embedded-5.5.58-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-embedded-devel-5.5.58-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-libs-5.5.58-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-server-5.5.58-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-test-5.5.58-1.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-config / mysql55 / mysql55-bench / mysql55-debuginfo / etc");
}
