#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0035. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127205);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-3136",
    "CVE-2018-3139",
    "CVE-2018-3149",
    "CVE-2018-3169",
    "CVE-2018-3180",
    "CVE-2018-3183",
    "CVE-2018-3214"
  );
  script_bugtraq_id(105617);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : java-1.8.0-openjdk Multiple Vulnerabilities (NS-SA-2019-0035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has java-1.8.0-openjdk packages installed that are
affected by multiple vulnerabilities:

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: Sound).
    Supported versions that are affected are Java SE: 6u201,
    7u191 and 8u182; Java SE Embedded: 8u181; JRockit:
    R28.3.19. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit. Note: This vulnerability
    applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the
    specified Component, e.g. through a web service which
    supplies data to the APIs. CVSS 3.0 Base Score 5.3
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2018-3214)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Networking). Supported
    versions that are affected are Java SE: 6u201, 7u191,
    8u182 and 11; Java SE Embedded: 8u181. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks require
    human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in
    unauthorized read access to a subset of Java SE, Java SE
    Embedded accessible data. Note: This vulnerability
    applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g. code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability does not apply to Java deployments,
    typically in servers, that load and run only trusted
    code (e.g. code installed by an administrator). CVSS 3.0
    Base Score 3.1 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N).
    (CVE-2018-3139)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: JSSE).
    Supported versions that are affected are Java SE: 6u201,
    7u191, 8u182 and 11; Java SE Embedded: 8u181; JRockit:
    R28.3.19. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via SSL/TLS
    to compromise Java SE, Java SE Embedded, JRockit.
    Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of
    Java SE, Java SE Embedded, JRockit accessible data as
    well as unauthorized read access to a subset of Java SE,
    Java SE Embedded, JRockit accessible data and
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE Embedded,
    JRockit. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets (in
    Java SE 8), that load and run untrusted code (e.g. code
    that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g.
    through a web service which supplies data to the APIs.
    CVSS 3.0 Base Score 5.6 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L).
    (CVE-2018-3180)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Security). Supported
    versions that are affected are Java SE: 6u201, 7u191,
    8u182 and 11; Java SE Embedded: 8u181. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks require
    human interaction from a person other than the attacker
    and while the vulnerability is in Java SE, Java SE
    Embedded, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access
    to some of Java SE, Java SE Embedded accessible data.
    Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8),
    that load and run untrusted code (e.g. code that comes
    from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run
    only trusted code (e.g. code installed by an
    administrator). CVSS 3.0 Base Score 3.4 (Integrity
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N).
    (CVE-2018-3136)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: JNDI).
    Supported versions that are affected are Java SE: 6u201,
    7u191, 8u182 and 11; Java SE Embedded: 8u181; JRockit:
    R28.3.19. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks require human
    interaction from a person other than the attacker and
    while the vulnerability is in Java SE, Java SE Embedded,
    JRockit, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in takeover of Java SE, Java SE Embedded,
    JRockit. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets (in
    Java SE 8), that load and run untrusted code (e.g. code
    that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g.
    through a web service which supplies data to the APIs.
    CVSS 3.0 Base Score 8.3 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).
    (CVE-2018-3149)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Hotspot). Supported
    versions that are affected are Java SE: 7u191, 8u182 and
    11; Java SE Embedded: 8u181. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks require human
    interaction from a person other than the attacker and
    while the vulnerability is in Java SE, Java SE Embedded,
    attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in
    takeover of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g. code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability does not apply to Java deployments,
    typically in servers, that load and run only trusted
    code (e.g. code installed by an administrator). CVSS 3.0
    Base Score 8.3 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).
    (CVE-2018-3169)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: Scripting).
    Supported versions that are affected are Java SE: 8u182
    and 11; Java SE Embedded: 8u181; JRockit: R28.3.19.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. While the vulnerability is in Java
    SE, Java SE Embedded, JRockit, attacks may significantly
    impact additional products. Successful attacks of this
    vulnerability can result in takeover of Java SE, Java SE
    Embedded, JRockit. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed
    Java Web Start applications or sandboxed Java applets
    (in Java SE 8), that load and run untrusted code (e.g.
    code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g.
    through a web service which supplies data to the APIs.
    CVSS 3.0 Base Score 9.0 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H).
    (CVE-2018-3183)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0035");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL java-1.8.0-openjdk packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "java-1.8.0-openjdk-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-accessibility-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-accessibility-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-debuginfo-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-demo-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-demo-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-devel-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-devel-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-headless-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-headless-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-javadoc-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-javadoc-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-javadoc-zip-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-src-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-src-debug-1.8.0.191.b12-0.el7_5"
  ],
  "CGSL MAIN 5.04": [
    "java-1.8.0-openjdk-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-accessibility-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-accessibility-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-debuginfo-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-demo-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-demo-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-devel-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-devel-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-headless-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-headless-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-javadoc-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-javadoc-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-javadoc-zip-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-src-1.8.0.191.b12-0.el7_5",
    "java-1.8.0-openjdk-src-debug-1.8.0.191.b12-0.el7_5"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk");
}
