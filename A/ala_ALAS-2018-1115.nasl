#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1115.
#

include("compat.inc");

if (description)
{
  script_id(119474);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/09");

  script_cve_id("CVE-2016-9843", "CVE-2018-3133", "CVE-2018-3143", "CVE-2018-3156", "CVE-2018-3174", "CVE-2018-3247", "CVE-2018-3251", "CVE-2018-3276", "CVE-2018-3278", "CVE-2018-3282");
  script_xref(name:"ALAS", value:"2018-1115");

  script_name(english:"Amazon Linux AMI : mysql56 (ALAS-2018-1115)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: InnoDB). Supported versions that are affected are
5.6.41 and prior, 5.7.23 and prior and 8.0.12 and prior. Easily
exploitable vulnerability allows low privileged attacker with network
access via multiple protocols to compromise MySQL Server. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of MySQL
Server. CVSS 3.0 Base Score 6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-3251)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: InnoDB). Supported versions that are affected are
5.6.41 and prior, 5.7.23 and prior and 8.0.12 and prior. Easily
exploitable vulnerability allows low privileged attacker with network
access via multiple protocols to compromise MySQL Server. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of MySQL
Server. CVSS 3.0 Base Score 6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-3156)

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
(subcomponent: InnoDB). Supported versions that are affected are
5.6.41 and prior, 5.7.23 and prior and 8.0.12 and prior. Easily
exploitable vulnerability allows low privileged attacker with network
access via multiple protocols to compromise MySQL Server. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of MySQL
Server. CVSS 3.0 Base Score 6.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-3143)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Merge). Supported versions that are affected
are 5.6.41 and prior, 5.7.23 and prior and 8.0.12 and prior. Easily
exploitable vulnerability allows high privileged attacker with network
access via multiple protocols to compromise MySQL Server. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of MySQL
Server as well as unauthorized update, insert or delete access to some
of MySQL Server accessible data. CVSS 3.0 Base Score 5.5 (Integrity
and Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H).(CVE-2018-3247)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Parser). Supported versions that are affected
are 5.5.61 and prior, 5.6.41 and prior, 5.7.23 and prior and 8.0.12
and prior. Easily exploitable vulnerability allows low privileged
attacker with network access via multiple protocols to compromise
MySQL Server. Successful attacks of this vulnerability can result in
unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of MySQL Server. CVSS 3.0 Base Score 6.5 (Availability
impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-3133)

The crc32_big function in crc32.c in zlib 1.2.8 might allow
context-dependent attackers to have unspecified impact via vectors
involving big-endian CRC calculation.(CVE-2016-9843)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: Memcached). Supported versions that are
affected are 5.6.41 and prior, 5.7.23 and prior and 8.0.12 and prior.
Easily exploitable vulnerability allows high privileged attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability impacts). CVSS
Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-3276)

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
Vector: (CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H).(CVE-2018-3174)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: Server: RBR). Supported versions that are affected are
5.6.41 and prior, 5.7.23 and prior and 8.0.12 and prior. Easily
exploitable vulnerability allows high privileged attacker with network
access via multiple protocols to compromise MySQL Server. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a hang or frequently repeatable crash (complete DOS) of MySQL
Server. CVSS 3.0 Base Score 4.9 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).(CVE-2018-3278)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1115.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update mysql56' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"mysql56-5.6.42-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-bench-5.6.42-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-common-5.6.42-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-debuginfo-5.6.42-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-devel-5.6.42-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-5.6.42-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-embedded-devel-5.6.42-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-errmsg-5.6.42-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-libs-5.6.42-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-server-5.6.42-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql56-test-5.6.42-1.31.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql56 / mysql56-bench / mysql56-common / mysql56-debuginfo / etc");
}
