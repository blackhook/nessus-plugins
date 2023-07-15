##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASJAVA-OPENJDK11-2021-001.
##

include('compat.inc');

if (description)
{
  script_id(160993);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2021-44228", "CVE-2021-45046");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"IAVA", value:"2022-A-0060");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/22");
  script_xref(name:"CEA-ID", value:"CEA-2021-0052");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"Amazon Linux 2 : java-11-openjdk (ALASJAVA-OPENJDK11-2021-001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of java-11-openjdk installed on the remote host is prior to 11.0.13.0.8-1. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2JAVA-OPENJDK11-2021-001 advisory.

  - Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI
    features used in configuration, log messages, and parameters do not protect against attacker controlled
    LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters
    can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From
    log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3,
    and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to
    log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.
    (CVE-2021-44228)

  - It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-
    default configurations. This could allows attackers with control over Thread Context Map (MDC) input data
    when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for
    example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input
    data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some
    environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix
    this issue by removing support for message lookup patterns and disabling JNDI functionality by default.
    (CVE-2021-45046)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASJAVA-OPENJDK11-2021-001.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44228.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-45046.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update java-11-openjdk' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44228");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-javadoc-zidebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-jmods-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-static-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-openjdk-static-libs-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'java-11-openjdk-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-debuginfo-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-debuginfo-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-demo-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-demo-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-demo-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-demo-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-devel-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-devel-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-devel-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-devel-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-headless-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-headless-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-headless-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-headless-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-zip-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-javadoc-zip-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-jmods-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-jmods-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-jmods-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-jmods-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-src-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-src-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-src-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-src-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-static-libs-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-static-libs-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-static-libs-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-openjdk-static-libs-debug-11.0.13.0.8-1.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var allowmaj = NULL;
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-debug / java-11-openjdk-debuginfo / etc");
}