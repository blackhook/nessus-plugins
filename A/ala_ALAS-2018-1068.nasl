#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1068.
#

include("compat.inc");

if (description)
{
  script_id(112095);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2018-2767", "CVE-2018-3058", "CVE-2018-3063", "CVE-2018-3066", "CVE-2018-3070", "CVE-2018-3081");
  script_xref(name:"ALAS", value:"2018-1068");

  script_name(english:"Amazon Linux AMI : mysql55 (ALAS-2018-1068)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Options). Supported versions that are affected
are 5.5.60 and prior. Difficult to exploit vulnerability allows high
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized update, insert or delete access to some of
MySQL Server accessible data as well as unauthorized read access to a
subset of MySQL Server accessible data. CVSS 3.0 Base Score 3.3
(Confidentiality and Integrity impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N).(CVE-2018-3066)

Vulnerability in the MySQL Client component of Oracle MySQL
(subcomponent: Client programs). Supported versions that are affected
are 5.5.60 and prior. Difficult to exploit vulnerability allows high
privileged attacker with network access via multiple protocols to
compromise MySQL Client. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Client as well as
unauthorized update, insert or delete access to some of MySQL Client
accessible data. CVSS 3.0 Base Score 5.0 (Integrity and Availability
impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H).(CVE-2018-3081)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Client mysqldump). Supported versions that are affected
are 5.5.60 and prior. Easily exploitable vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-3070)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Security: Encryption). Supported versions that
are affected are 5.5.60 and prior. Difficult to exploit vulnerability
allows low privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized read access to a subset of
MySQL Server accessible data. CVSS 3.0 Base Score 3.1 (Confidentiality
impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N).(CVE-2018-2767)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: MyISAM). Supported versions that are affected are
5.5.60 and prior. Easily exploitable vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized update, insert or delete access to some of
MySQL Server accessible data. CVSS 3.0 Base Score 4.3 (Integrity
impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N).(CVE-2018-3058)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Security: Privileges). Supported versions that
are affected are 5.5.60 and prior. Easily exploitable vulnerability
allows high privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0
Base Score 4.9 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-3063)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1068.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql55' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/24");
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
if (rpm_check(release:"ALA", reference:"mysql-config-5.5.61-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-5.5.61-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-bench-5.5.61-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-debuginfo-5.5.61-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-devel-5.5.61-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-embedded-5.5.61-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-embedded-devel-5.5.61-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-libs-5.5.61-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-server-5.5.61-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-test-5.5.61-1.22.amzn1")) flag++;

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
