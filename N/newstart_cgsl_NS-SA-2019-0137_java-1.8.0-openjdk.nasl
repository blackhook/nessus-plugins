#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0137. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127397);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-2790",
    "CVE-2018-2794",
    "CVE-2018-2795",
    "CVE-2018-2796",
    "CVE-2018-2797",
    "CVE-2018-2798",
    "CVE-2018-2799",
    "CVE-2018-2800",
    "CVE-2018-2814",
    "CVE-2018-2815",
    "CVE-2018-2952",
    "CVE-2018-3639"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : java-1.8.0-openjdk Multiple Vulnerabilities (NS-SA-2019-0137)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has java-1.8.0-openjdk packages installed that are affected by
multiple vulnerabilities:

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of Load & Store instructions (a commonly used
    performance optimization). It relies on the presence of
    a precisely-defined instruction sequence in the
    privileged code as well as the fact that memory read
    from address to which a recent memory write has occurred
    may see an older value and subsequently cause an update
    into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to read privileged memory by
    conducting targeted cache side-channel attacks.
    (CVE-2018-3639)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Hotspot). Supported
    versions that are affected are Java SE: 6u181, 7u171,
    8u162 and 10; Java SE Embedded: 8u161. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks require
    human interaction from a person other than the attacker
    and while the vulnerability is in Java SE, Java SE
    Embedded, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in takeover of Java SE, Java SE Embedded. Note:
    This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and
    run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security.
    This vulnerability does not apply to Java deployments,
    typically in servers, that load and run only trusted
    code (e.g., code installed by an administrator). CVSS
    3.0 Base Score 8.3 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).
    (CVE-2018-2814)

  - Vulnerability in the Java SE, JRockit component of
    Oracle Java SE (subcomponent: Security). Supported
    versions that are affected are Java SE: 6u181, 7u171,
    8u162, 10 and JRockit: R28.3.17. Difficult to exploit
    vulnerability allows unauthenticated attacker with logon
    to the infrastructure where Java SE, JRockit executes to
    compromise Java SE, JRockit. Successful attacks require
    human interaction from a person other than the attacker
    and while the vulnerability is in Java SE, JRockit,
    attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in
    takeover of Java SE, JRockit. Note: Applies to client
    and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications
    and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 7.7 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).
    (CVE-2018-2794)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: Security).
    Supported versions that are affected are Java SE: 6u181,
    7u171, 8u162 and 10; Java SE Embedded: 8u161; JRockit:
    R28.3.17. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit. Note: Applies to client
    and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications
    and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2018-2795)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent:
    Serialization). Supported versions that are affected are
    Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded:
    8u161; JRockit: R28.3.17. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded, JRockit. Successful attacks of
    this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit. Note: Applies to client
    and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications
    and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2018-2815)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: JAXP).
    Supported versions that are affected are Java SE: 7u171,
    8u162 and 10; Java SE Embedded: 8u161; JRockit:
    R28.3.17. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit. Note: Applies to client
    and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications
    and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2018-2799)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: AWT).
    Supported versions that are affected are Java SE: 6u181,
    7u171, 8u162 and 10; Java SE Embedded: 8u161; JRockit:
    R28.3.17. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit. Note: Applies to client
    and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications
    and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2018-2798)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: JMX).
    Supported versions that are affected are Java SE: 6u181,
    7u171, 8u162 and 10; Java SE Embedded: 8u161; JRockit:
    R28.3.17. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit. Note: Applies to client
    and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications
    and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2018-2797)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: Concurrency).
    Supported versions that are affected are Java SE: 7u171,
    8u162 and 10; Java SE Embedded: 8u161; JRockit:
    R28.3.17. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit. Note: Applies to client
    and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications
    and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2018-2796)

  - Vulnerability in the Java SE, JRockit component of
    Oracle Java SE (subcomponent: RMI). Supported versions
    that are affected are Java SE: 6u181, 7u171 and 8u162;
    JRockit: R28.3.17. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, JRockit.
    Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized update,
    insert or delete access to some of Java SE, JRockit
    accessible data as well as unauthorized read access to a
    subset of Java SE, JRockit accessible data. Note: This
    vulnerability can only be exploited by supplying data to
    APIs in the specified Component without using Untrusted
    Java Web Start applications or Untrusted Java applets,
    such as through a web service. CVSS 3.0 Base Score 4.2
    (Confidentiality and Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N).
    (CVE-2018-2800)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Security). Supported
    versions that are affected are Java SE: 6u181, 7u171,
    8u162 and 10; Java SE Embedded: 8u161. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks require
    human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of
    Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability does
    not apply to Java deployments, typically in servers,
    that load and run only trusted code (e.g., code
    installed by an administrator). CVSS 3.0 Base Score 3.1
    (Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N).
    (CVE-2018-2790)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: Concurrency).
    Supported versions that are affected are Java SE: 6u191,
    7u181, 8u172 and 10.0.1; Java SE Embedded: 8u171;
    JRockit: R28.3.18. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit. Note: Applies to client
    and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications
    and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 3.7 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2018-2952)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0137");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL java-1.8.0-openjdk packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2814");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "java-1.8.0-openjdk-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-debug-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-debuginfo-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-demo-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-demo-debug-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-devel-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-devel-debug-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-headless-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-headless-debug-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-javadoc-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-javadoc-debug-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-src-1.8.0.181-3.b13.el6_10",
    "java-1.8.0-openjdk-src-debug-1.8.0.181-3.b13.el6_10"
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
