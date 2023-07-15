#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1753.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158214);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id(
    "CVE-2022-21248",
    "CVE-2022-21277",
    "CVE-2022-21282",
    "CVE-2022-21283",
    "CVE-2022-21291",
    "CVE-2022-21293",
    "CVE-2022-21294",
    "CVE-2022-21296",
    "CVE-2022-21299",
    "CVE-2022-21305",
    "CVE-2022-21340",
    "CVE-2022-21341",
    "CVE-2022-21360",
    "CVE-2022-21365",
    "CVE-2022-21366"
  );
  script_xref(name:"IAVA", value:"2022-A-0031-S");
  script_xref(name:"ALAS", value:"2022-1753");

  script_name(english:"Amazon Linux 2 : java-11-amazon-corretto (ALAS-2022-1753)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of java-11-amazon-corretto installed on the remote host is prior to 11.0.14+9-1. It is, therefore, affected
by multiple vulnerabilities as referenced in the ALAS2-2022-1753 advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Serialization). Supported versions that are affected are Oracle Java SE: 7u321, 8u311,
    11.0.13, 17.01; Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible
    data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by
    using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS
    3.1 Base Score 3.7 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N).
    (CVE-2022-21248)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: ImageIO). Supported versions that are affected are Oracle Java SE: 11.0.13, 17.01; Oracle
    GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1
    Base Score 5.3 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2022-21277, CVE-2022-21366)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JAXP). Supported versions that are affected are Oracle Java SE: 7u321, 8u311, 11.0.13, 17.01;
    Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized read
    access to a subset of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1
    Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).
    (CVE-2022-21282, CVE-2022-21296)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 11.0.13, 17.01; Oracle
    GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1
    Base Score 5.3 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2022-21283)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Hotspot). Supported versions that are affected are Oracle Java SE: 7u321, 8u311, 11.0.13,
    17.01; Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1
    Base Score 5.3 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N).
    (CVE-2022-21291, CVE-2022-21305)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 7u321, 8u311, 11.0.13,
    17.01; Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1
    Base Score 5.3 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2022-21293, CVE-2022-21294, CVE-2022-21340)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JAXP). Supported versions that are affected are Oracle Java SE: 7u321, 8u311, 11.0.13, 17.01;
    Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1
    Base Score 5.3 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2022-21299)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Serialization). Supported versions that are affected are Oracle Java SE: 7u321, 8u311,
    11.0.13, 17.01; Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise
    Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by
    using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS
    3.1 Base Score 5.3 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2022-21341)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: ImageIO). Supported versions that are affected are Oracle Java SE: 7u321, 8u311, 11.0.13,
    17.01; Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1
    Base Score 5.3 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2022-21360, CVE-2022-21365)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1753.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21248.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21277.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21282.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21283.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21291.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21293.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21294.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21296.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21299.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21305.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21340.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21341.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21360.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21365.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21366.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update java-11-amazon-corretto' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-amazon-corretto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-amazon-corretto-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-amazon-corretto-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'java-11-amazon-corretto-11.0.14+9-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-amazon-corretto-11.0.14+9-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-amazon-corretto-headless-11.0.14+9-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-amazon-corretto-headless-11.0.14+9-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-amazon-corretto-javadoc-11.0.14+9-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-11-amazon-corretto-javadoc-11.0.14+9-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-amazon-corretto / java-11-amazon-corretto-headless / java-11-amazon-corretto-javadoc");
}