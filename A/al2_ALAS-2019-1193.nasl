#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1193.
#

include("compat.inc");

if (description)
{
  script_id(124128);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/23");

  script_cve_id("CVE-2016-9843", "CVE-2018-3174", "CVE-2018-3282");
  script_xref(name:"ALAS", value:"2019-1193");

  script_name(english:"Amazon Linux 2 : mariadb (ALAS-2019-1193)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The crc32_big function in crc32.c in zlib 1.2.8 might allow
context-dependent attackers to have unspecified impact via vectors
involving big-endian CRC calculation.(CVE-2016-9843)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Storage Engines). Supported versions that are
affected are 5.5.61 and prior, 5.6.41 and prior, 5.7.23 and prior and
8.0.12 and prior. Easily exploitable vulnerability allows high
privileged attacker with network access via multiple protocols to
compromise MySQL Server. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score
4.9 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-3282)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Client programs). Supported versions that are affected
are 5.5.61 and prior, 5.6.41 and prior, 5.7.23 and prior and 8.0.12
and prior. Difficult to exploit vulnerability allows high privileged
attacker with logon to the infrastructure where MySQL Server executes
to compromise MySQL Server. While the vulnerability is in MySQL
Server, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of MySQL Server. CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
Vector: (CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H).(CVE-2018-3174)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1193.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mariadb' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"mariadb-5.5.62-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-bench-5.5.62-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-debuginfo-5.5.62-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-devel-5.5.62-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-embedded-5.5.62-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-embedded-devel-5.5.62-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-libs-5.5.62-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-server-5.5.62-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mariadb-test-5.5.62-1.amzn2.0.1")) flag++;

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
