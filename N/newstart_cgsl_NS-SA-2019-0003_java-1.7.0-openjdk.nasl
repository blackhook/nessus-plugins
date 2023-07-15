#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0003. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127144);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-10193",
    "CVE-2017-10198",
    "CVE-2017-10274",
    "CVE-2017-10281",
    "CVE-2017-10285",
    "CVE-2017-10295",
    "CVE-2017-10345",
    "CVE-2017-10346",
    "CVE-2017-10347",
    "CVE-2017-10348",
    "CVE-2017-10349",
    "CVE-2017-10350",
    "CVE-2017-10355",
    "CVE-2017-10356",
    "CVE-2017-10357",
    "CVE-2017-10388"
  );

  script_name(english:"NewStart CGSL MAIN 5.04 : java-1.7.0-openjdk Multiple Vulnerabilities (NS-SA-2019-0003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 5.04, has java-1.7.0-openjdk packages installed that are affected by
multiple vulnerabilities:

  - It was discovered that the Security component of OpenJDK
    could fail to properly enforce restrictions defined for
    processing of X.509 certificate chains. A remote
    attacker could possibly use this flaw to make Java
    accept certificate using one of the disabled algorithms.
    (CVE-2017-10198)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Security). Supported
    versions that are affected are Java SE: 6u151, 7u141 and
    8u131; Java SE Embedded: 8u131. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks require human
    interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in
    unauthorized read access to a subset of Java SE, Java SE
    Embedded accessible data. Note: This vulnerability
    applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability does
    not apply to Java deployments, typically in servers,
    that load and run only trusted code (e.g., code
    installed by an administrator). CVSS 3.0 Base Score 3.1
    (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N).
    (CVE-2017-10193)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: JAXP). Supported
    versions that are affected are Java SE: 6u161, 7u151,
    8u144 and 9; Java SE Embedded: 8u144. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply
    to Java deployments, typically in servers, that load and
    run only trusted code (e.g., code installed by an
    administrator). CVSS 3.0 Base Score 5.3 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2017-10349)

  - It was found that the FtpClient implementation in the
    Networking component of OpenJDK did not set connect and
    read timeouts by default. A malicious FTP server or a
    man-in-the-middle attacker could use this flaw to block
    execution of a Java application connecting to an FTP
    server. (CVE-2017-10355)

  - It was found that the HttpURLConnection and
    HttpsURLConnection classes in the Networking component
    of OpenJDK failed to check for newline characters
    embedded in URLs. An attacker able to make a Java
    application perform an HTTP request using an attacker
    provided URL could possibly inject additional headers
    into the request. (CVE-2017-10295)

  - It was discovered that the Security component of OpenJDK
    generated weak password-based encryption keys used to
    protect private keys stored in key stores. This made it
    easier to perform password guessing attacks to decrypt
    stored keys if an attacker could gain access to a key
    store. (CVE-2017-10356)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Libraries). Supported
    versions that are affected are Java SE: 6u161, 7u151,
    8u144 and 9; Java SE Embedded: 8u144. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply
    to Java deployments, typically in servers, that load and
    run only trusted code (e.g., code installed by an
    administrator). CVSS 3.0 Base Score 5.3 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2017-10348)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent:
    Serialization). Supported versions that are affected are
    Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded:
    8u144; JRockit: R28.3.15. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded, JRockit. Successful attacks of
    this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit. Note: This vulnerability
    can be exploited through sandboxed Java Web Start
    applications and sandboxed Java applets. It can also be
    exploited by supplying data to APIs in the specified
    Component without using sandboxed Java Web Start
    applications or sandboxed Java applets, such as through
    a web service. CVSS 3.0 Base Score 5.3 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2017-10281)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent:
    Serialization). Supported versions that are affected are
    Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded:
    8u144; JRockit: R28.3.15. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded, JRockit. Successful attacks
    require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial denial
    of service (partial DOS) of Java SE, Java SE Embedded,
    JRockit. Note: This vulnerability can be exploited
    through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 3.1 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L).
    (CVE-2017-10345)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Serialization).
    Supported versions that are affected are Java SE: 6u161,
    7u151, 8u144 and 9; Java SE Embedded: 8u144. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a partial denial of service (partial DOS) of
    Java SE, Java SE Embedded. Note: This vulnerability
    applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability does
    not apply to Java deployments, typically in servers,
    that load and run only trusted code (e.g., code
    installed by an administrator). CVSS 3.0 Base Score 5.3
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2017-10357)

  - It was discovered that the Kerberos client
    implementation in the Libraries component of OpenJDK
    used the sname field from the plain text part rather
    than encrypted part of the KDC reply message. A man-in-
    the-middle attacker could possibly use this flaw to
    impersonate Kerberos services to Java applications
    acting as Kerberos clients. (CVE-2017-10388)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: JAX-WS). Supported
    versions that are affected are Java SE: 7u151, 8u144 and
    9; Java SE Embedded: 8u144. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply
    to Java deployments, typically in servers, that load and
    run only trusted code (e.g., code installed by an
    administrator). CVSS 3.0 Base Score 5.3 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2017-10350)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Hotspot). Supported
    versions that are affected are Java SE: 6u161, 7u151,
    8u144 and 9; Java SE Embedded: 8u144. Easily exploitable
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
    sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability does
    not apply to Java deployments, typically in servers,
    that load and run only trusted code (e.g., code
    installed by an administrator). CVSS 3.0 Base Score 9.6
    (Confidentiality, Integrity and Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H).
    (CVE-2017-10346)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: RMI). Supported
    versions that are affected are Java SE: 6u161, 7u151,
    8u144 and 9; Java SE Embedded: 8u144. Easily exploitable
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
    sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability does
    not apply to Java deployments, typically in servers,
    that load and run only trusted code (e.g., code
    installed by an administrator). CVSS 3.0 Base Score 9.6
    (Confidentiality, Integrity and Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H).
    (CVE-2017-10285)

  - Vulnerability in the Java SE, JRockit component of
    Oracle Java SE (subcomponent: Serialization). Supported
    versions that are affected are Java SE: 6u161, 7u151,
    8u144 and 9; Java SE Embedded: 8u144. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, JRockit. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a partial
    denial of service (partial DOS) of Java SE, JRockit.
    Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and
    run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security.
    This vulnerability does not apply to Java deployments,
    typically in servers, that load and run only trusted
    code (e.g., code installed by an administrator). CVSS
    3.0 Base Score 5.3 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2017-10347)

  - Vulnerability in the Java SE component of Oracle Java SE
    (subcomponent: Smart Card IO). Supported versions that
    are affected are Java SE: 6u161, 7u151, 8u144 and 9.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. Successful
    attacks require human interaction from a person other
    than the attacker. Successful attacks of this
    vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all
    Java SE accessible data as well as unauthorized access
    to critical data or complete access to all Java SE
    accessible data. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed
    Java Web Start applications or sandboxed Java applets,
    that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an
    administrator). CVSS 3.0 Base Score 6.8 (Confidentiality
    and Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N).
    (CVE-2017-10274)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0003");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL java-1.7.0-openjdk packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10346");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
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

if (release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 5.04": [
    "java-1.7.0-openjdk-1.7.0.161-2.6.12.0.el7_4",
    "java-1.7.0-openjdk-accessibility-1.7.0.161-2.6.12.0.el7_4",
    "java-1.7.0-openjdk-debuginfo-1.7.0.161-2.6.12.0.el7_4",
    "java-1.7.0-openjdk-demo-1.7.0.161-2.6.12.0.el7_4",
    "java-1.7.0-openjdk-devel-1.7.0.161-2.6.12.0.el7_4",
    "java-1.7.0-openjdk-headless-1.7.0.161-2.6.12.0.el7_4",
    "java-1.7.0-openjdk-javadoc-1.7.0.161-2.6.12.0.el7_4",
    "java-1.7.0-openjdk-src-1.7.0.161-2.6.12.0.el7_4"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk");
}
