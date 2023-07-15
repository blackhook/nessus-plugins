#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0124. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127372);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2018-2579",
    "CVE-2018-2588",
    "CVE-2018-2599",
    "CVE-2018-2602",
    "CVE-2018-2603",
    "CVE-2018-2618",
    "CVE-2018-2629",
    "CVE-2018-2633",
    "CVE-2018-2634",
    "CVE-2018-2637",
    "CVE-2018-2641",
    "CVE-2018-2663",
    "CVE-2018-2677",
    "CVE-2018-2678"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : java-1.7.0-openjdk Multiple Vulnerabilities (NS-SA-2019-0124)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has java-1.7.0-openjdk packages installed that are affected by
multiple vulnerabilities:

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: JNDI).
    Supported versions that are affected are Java SE: 6u171,
    7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151;
    JRockit: R28.3.16. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks require human
    interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE Embedded,
    JRockit. Note: This vulnerability applies to client and
    server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications
    and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 4.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L).
    (CVE-2018-2678)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: AWT). Supported
    versions that are affected are Java SE: 6u171, 7u161,
    8u152 and 9.0.1; Java SE Embedded: 8u151. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks
    require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial denial
    of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and
    run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security.
    This vulnerability does not apply to Java deployments,
    typically in servers, that load and run only trusted
    code (e.g., code installed by an administrator). CVSS
    3.0 Base Score 4.3 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L).
    (CVE-2018-2677)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent: Libraries).
    Supported versions that are affected are Java SE: 6u171,
    7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151;
    JRockit: R28.3.16. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks require human
    interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE Embedded,
    JRockit. Note: This vulnerability applies to client and
    server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications
    and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service.
    CVSS 3.0 Base Score 4.3 (Availability impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L).
    (CVE-2018-2663)

  - It was discovered that multiple encryption key classes
    in the Libraries component of OpenJDK did not properly
    synchronize access to their internal data. This could
    possibly cause a multi-threaded Java application to
    apply weak encryption to data because of the use of a
    key that was zeroed out. (CVE-2018-2579)

  - It was discovered that the LDAP component of OpenJDK
    failed to properly encode special characters in user
    names when adding them to an LDAP search query. A remote
    attacker could possibly use this flaw to manipulate LDAP
    queries performed by the LdapLoginModule class.
    (CVE-2018-2588)

  - It was discovered that the I18n component of OpenJDK
    could use an untrusted search path when loading resource
    bundle classes. A local attacker could possibly use this
    flaw to execute arbitrary code as another local user by
    making their Java application load an attacker
    controlled class file. (CVE-2018-2602)

  - It was discovered that the DNS client implementation in
    the JNDI component of OpenJDK did not use random source
    ports when sending out DNS queries. This could make it
    easier for a remote attacker to spoof responses to those
    queries. (CVE-2018-2599)

  - It was discovered that the Libraries component of
    OpenJDK failed to sufficiently limit the amount of
    memory allocated when reading DER encoded input. A
    remote attacker could possibly use this flaw to make a
    Java application use an excessive amount of memory if it
    parsed attacker supplied DER encoded input.
    (CVE-2018-2603)

  - It was discovered that the JGSS component of OpenJDK
    failed to properly handle GSS context in the native GSS
    library wrapper in certain cases. A remote attacker
    could possibly make a Java application using JGSS to use
    a previously freed context. (CVE-2018-2629)

  - It was discovered that the key agreement implementations
    in the JCE component of OpenJDK did not guarantee
    sufficient strength of used keys to adequately protect
    generated shared secret. This could make it easier to
    break data encryption by attacking key agreement rather
    than the encryption using the negotiated secret.
    (CVE-2018-2618)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: AWT). Supported
    versions that are affected are Java SE: 6u171, 7u161,
    8u152 and 9.0.1; Java SE Embedded: 8u151. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks require
    human interaction from a person other than the attacker
    and while the vulnerability is in Java SE, Java SE
    Embedded, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in unauthorized creation, deletion or
    modification access to critical data or all Java SE,
    Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability does
    not apply to Java deployments, typically in servers,
    that load and run only trusted code (e.g., code
    installed by an administrator). CVSS 3.0 Base Score 6.1
    (Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N).
    (CVE-2018-2641)

  - The JGSS component of OpenJDK ignores the value of the
    javax.security.auth.useSubjectCredsOnly property when
    using HTTP/SPNEGO authentication and always uses global
    credentials. It was discovered that this could cause
    global credentials to be unexpectedly used by an
    untrusted Java application. (CVE-2018-2634)

  - It was discovered that the JMX component of OpenJDK
    failed to properly set the deserialization filter for
    the SingleEntryRegistry in certain cases. A remote
    attacker could possibly use this flaw to bypass intended
    deserialization restrictions. (CVE-2018-2637)

  - It was discovered that the LDAPCertStore class in the
    JNDI component of OpenJDK failed to securely handle LDAP
    referrals. An attacker could possibly use this flaw to
    make it fetch attacker controlled certificate data.
    (CVE-2018-2633)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0124");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL java-1.7.0-openjdk packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2637");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2633");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "java-1.7.0-openjdk-1.7.0.171-2.6.13.0.el6_9",
    "java-1.7.0-openjdk-debuginfo-1.7.0.171-2.6.13.0.el6_9",
    "java-1.7.0-openjdk-demo-1.7.0.171-2.6.13.0.el6_9",
    "java-1.7.0-openjdk-devel-1.7.0.171-2.6.13.0.el6_9",
    "java-1.7.0-openjdk-javadoc-1.7.0.171-2.6.13.0.el6_9",
    "java-1.7.0-openjdk-src-1.7.0.171-2.6.13.0.el6_9"
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
