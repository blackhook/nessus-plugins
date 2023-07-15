#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-037.
##

include('compat.inc');

if (description)
{
  script_id(164729);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/06");

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

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-037)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-037 advisory.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-037.html");
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
"Run 'dnf update --releasever=2022.0.20220308 java-latest-openjdk' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-demo-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-demo-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-devel-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-devel-fastdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-devel-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-devel-slowdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-fastdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-headless-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-headless-fastdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-headless-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-headless-slowdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-jmods-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-jmods-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-slowdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-src-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-src-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-static-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-static-libs-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-latest-openjdk-static-libs-slowdebug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'java-latest-openjdk-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-debugsource-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-debugsource-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-debugsource-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-demo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-demo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-demo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-demo-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-demo-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-demo-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-demo-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-demo-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-fastdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-fastdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-slowdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-slowdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-devel-slowdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-fastdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-fastdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-fastdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-fastdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-slowdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-slowdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-headless-slowdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-javadoc-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-javadoc-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-javadoc-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-javadoc-zip-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-javadoc-zip-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-javadoc-zip-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-jmods-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-jmods-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-jmods-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-jmods-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-jmods-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-jmods-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-jmods-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-jmods-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-slowdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-slowdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-slowdebug-debuginfo-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-src-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-src-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-src-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-src-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-src-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-src-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-src-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-src-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-static-libs-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-static-libs-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-static-libs-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-static-libs-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-static-libs-fastdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-static-libs-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-static-libs-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-latest-openjdk-static-libs-slowdebug-17.0.2.0.8-2.rolling.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-latest-openjdk / java-latest-openjdk-debuginfo / java-latest-openjdk-debugsource / etc");
}