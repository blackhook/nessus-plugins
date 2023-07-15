#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1515.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151515);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-2163");
  script_xref(name:"IAVA", value:"2021-A-0195");
  script_xref(name:"ALAS", value:"2021-1515");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Amazon Linux AMI : java-1.8.0-openjdk (ALAS-2021-1515)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of java-1.8.0-openjdk installed on the remote host is prior to 1.8.0.292.b10-1.63. It is, therefore,
affected by a vulnerability as referenced in the ALAS-2021-1515 advisory.

  - Vulnerability in the Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition product of Oracle Java
    SE (component: Libraries). Supported versions that are affected are Java SE: 7u291, 8u281, 11.0.10, 16;
    Java SE Embedded: 8u281; Oracle GraalVM Enterprise Edition: 19.3.5, 20.3.1.2 and 21.0.0.2. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Java SE, Java SE Embedded,
    Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments
    that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox
    for security. CVSS 3.1 Base Score 5.3 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N). (CVE-2021-2163)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1515.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2163");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update java-1.8.0-openjdk' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2163");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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

pkgs = [
    {'reference':'java-1.8.0-openjdk-1.8.0.292.b10-1.63.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-1.8.0.292.b10-1.63.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-debuginfo-1.8.0.292.b10-1.63.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-debuginfo-1.8.0.292.b10-1.63.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.292.b10-1.63.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.292.b10-1.63.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.292.b10-1.63.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.292.b10-1.63.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.292.b10-1.63.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.292.b10-1.63.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.292.b10-1.63.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-javadoc-zip-1.8.0.292.b10-1.63.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.292.b10-1.63.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.292.b10-1.63.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-debuginfo / java-1.8.0-openjdk-demo / etc");
}