#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1695.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153152);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-2341", "CVE-2021-2369", "CVE-2021-2388");
  script_xref(name:"IAVA", value:"2021-A-0327-S");
  script_xref(name:"ALAS", value:"2021-1695");

  script_name(english:"Amazon Linux 2 : java-1.8.0-openjdk (ALAS-2021-1695)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of java-1.8.0-openjdk installed on the remote host is prior to 1.8.0.302.b08-0. It is, therefore, affected
by multiple vulnerabilities as referenced in the ALAS2-2021-1695 advisory.

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Networking). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle
    GraalVM Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise
    Edition. Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 3.1 (Confidentiality
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N). (CVE-2021-2341)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Library). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.2 and 21.1.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 4.3 (Integrity impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N). (CVE-2021-2369)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Hotspot). Supported versions that are affected are Java SE: 8u291, 11.0.11, 16.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in takeover of Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). CVSS 3.1 Base Score 7.5 (Confidentiality, Integrity and Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H). (CVE-2021-2388)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1695.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2341");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2369");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2388");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update java-1.8.0-openjdk' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
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
    {'reference':'java-1.8.0-openjdk-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-accessibility-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-debuginfo-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-debuginfo-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-debuginfo-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.302.b08-0.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-javadoc-debug-1.8.0.302.b08-0.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-javadoc-zip-1.8.0.302.b08-0.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.302.b08-0.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-debug-1.8.0.302.b08-0.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / java-1.8.0-openjdk-accessibility-debug / etc");
}