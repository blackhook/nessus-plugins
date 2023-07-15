#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1333.
#

include("compat.inc");

if (description)
{
  script_id(132757);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/15");

  script_cve_id("CVE-2019-2911", "CVE-2019-2914", "CVE-2019-2938", "CVE-2019-2946", "CVE-2019-2960", "CVE-2019-2974", "CVE-2019-2993");
  script_xref(name:"ALAS", value:"2020-1333");

  script_name(english:"Amazon Linux AMI : mysql57 (ALAS-2020-1333)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the MySQL Server product of Oracle MySQL (component:
Information Schema). Supported versions that are affected are 5.6.45
and prior, 5.7.27 and prior and 8.0.17 and prior. Easily exploitable
vulnerability allows high privileged attacker with network access via
multiple protocols to compromise MySQL Server. Successful attacks of
this vulnerability can result in unauthorized read access to a subset
of MySQL Server accessible data. CVSS 3.0 Base Score 2.7
(Confidentiality impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N).(CVE-2019-2911)

Vulnerability in the MySQL Server product of Oracle MySQL (component:
Server: Security: Encryption). Supported versions that are affected
are 5.7.27 and prior and 8.0.17 and prior. Easily exploitable
vulnerability allows low privileged attacker with network access via
multiple protocols to compromise MySQL Server. Successful attacks of
this vulnerability can result in unauthorized ability to cause a hang
or frequently repeatable crash (complete DOS) of MySQL Server. CVSS
3.0 Base Score 6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2019-2914)

Vulnerability in the MySQL Server product of Oracle MySQL (component:
InnoDB). Supported versions that are affected are 5.7.27 and prior and
8.0.17 and prior. Difficult to exploit vulnerability allows high
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
4.4 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).(CVE-2019-2938)

Vulnerability in the MySQL Server product of Oracle MySQL (component:
Server: PS). Supported versions that are affected are 5.7.27 and prior
and 8.0.17 and prior. Easily exploitable vulnerability allows low
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2019-2946)

Vulnerability in the MySQL Server product of Oracle MySQL (component:
Server: Replication). Supported versions that are affected are 5.7.27
and prior and 8.0.17 and prior. Easily exploitable vulnerability
allows high privileged attacker with network access via multiple
protocols to compromise MySQL Server. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or
frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0
Base Score 4.9 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).(CVE-2019-2960)

Vulnerability in the MySQL Server product of Oracle MySQL (component:
Server: Optimizer). Supported versions that are affected are 5.6.45
and prior, 5.7.27 and prior and 8.0.17 and prior. Easily exploitable
vulnerability allows low privileged attacker with network access via
multiple protocols to compromise MySQL Server. Successful attacks of
this vulnerability can result in unauthorized ability to cause a hang
or frequently repeatable crash (complete DOS) of MySQL Server. CVSS
3.0 Base Score 6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2019-2974)

Vulnerability in the MySQL Server product of Oracle MySQL (component:
Server: C API). Supported versions that are affected are 5.7.27 and
prior and 8.0.17 and prior. Difficult to exploit vulnerability allows
low privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
5.3 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2019-2993)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1333.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql57' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2911");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"mysql57-5.7.28-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-common-5.7.28-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-debuginfo-5.7.28-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-devel-5.7.28-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-embedded-5.7.28-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-embedded-devel-5.7.28-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-errmsg-5.7.28-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-libs-5.7.28-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-server-5.7.28-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql57-test-5.7.28-1.14.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql57 / mysql57-common / mysql57-debuginfo / mysql57-devel / etc");
}
