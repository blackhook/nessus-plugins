##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1537.
##

include('compat.inc');

if (description)
{
  script_id(142022);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2019-2737",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2805",
    "CVE-2019-2974",
    "CVE-2020-2574",
    "CVE-2020-2752",
    "CVE-2020-2780",
    "CVE-2020-2812",
    "CVE-2020-2922"
  );
  script_bugtraq_id(109243);
  script_xref(name:"ALAS", value:"2020-1537");

  script_name(english:"Amazon Linux 2 : mariadb (ALAS-2020-1537)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1537 advisory.

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server : Pluggable Auth).
    Supported versions that are affected are 5.6.44 and prior, 5.7.26 and prior and 8.0.16 and prior. Easily
    exploitable vulnerability allows high privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9
    (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2019-2737)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Security: Privileges).
    Supported versions that are affected are 5.6.44 and prior, 5.7.26 and prior and 8.0.16 and prior. Easily
    exploitable vulnerability allows high privileged attacker with logon to the infrastructure where MySQL
    Server executes to compromise MySQL Server. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server as well
    as unauthorized update, insert or delete access to some of MySQL Server accessible data. CVSS 3.0 Base
    Score 5.1 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H). (CVE-2019-2739)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: XML). Supported
    versions that are affected are 5.6.44 and prior, 5.7.26 and prior and 8.0.16 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2019-2740)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Parser). Supported
    versions that are affected are 5.6.44 and prior, 5.7.26 and prior and 8.0.16 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2019-2805)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.6.45 and prior, 5.7.27 and prior and 8.0.17 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2019-2974)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.46 and prior, 5.7.28 and prior and 8.0.18 and prior. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. CVSS 3.0 Base Score 5.9 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2574)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.47 and prior, 5.7.27 and prior and 8.0.17 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2752)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 6.5 (Availability
    impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2780)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability
    impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-2812)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.18 and prior. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized read access to a subset of MySQL
    Client accessible data. CVSS 3.0 Base Score 3.7 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N). (CVE-2020-2922)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1537.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2737");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2739");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2740");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2805");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-2974");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2574");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2752");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2780");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2812");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2922");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update mariadb' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2922");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2739");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/28");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = [
    {'reference':'mariadb-5.5.68-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mariadb-5.5.68-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mariadb-5.5.68-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mariadb-bench-5.5.68-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mariadb-bench-5.5.68-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mariadb-bench-5.5.68-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mariadb-debuginfo-5.5.68-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mariadb-debuginfo-5.5.68-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mariadb-debuginfo-5.5.68-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mariadb-devel-5.5.68-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mariadb-devel-5.5.68-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mariadb-devel-5.5.68-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mariadb-embedded-5.5.68-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mariadb-embedded-5.5.68-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mariadb-embedded-5.5.68-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mariadb-embedded-devel-5.5.68-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mariadb-embedded-devel-5.5.68-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mariadb-embedded-devel-5.5.68-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mariadb-libs-5.5.68-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mariadb-libs-5.5.68-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mariadb-libs-5.5.68-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mariadb-server-5.5.68-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mariadb-server-5.5.68-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mariadb-server-5.5.68-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mariadb-test-5.5.68-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mariadb-test-5.5.68-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mariadb-test-5.5.68-1.amzn2', 'cpu':'x86_64', 'release':'AL2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb / mariadb-bench / mariadb-debuginfo / etc");
}