#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0111. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127348);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2016-3458",
    "CVE-2016-3500",
    "CVE-2016-3508",
    "CVE-2016-3550",
    "CVE-2016-3587",
    "CVE-2016-3598",
    "CVE-2016-3606",
    "CVE-2016-3610",
    "CVE-2016-5542",
    "CVE-2016-5546",
    "CVE-2016-5547",
    "CVE-2016-5548",
    "CVE-2016-5552",
    "CVE-2016-5554",
    "CVE-2016-5573",
    "CVE-2016-5582",
    "CVE-2016-5597",
    "CVE-2016-10165",
    "CVE-2017-3231",
    "CVE-2017-3241",
    "CVE-2017-3252",
    "CVE-2017-3253",
    "CVE-2017-3261",
    "CVE-2017-3272",
    "CVE-2017-3289",
    "CVE-2017-3509",
    "CVE-2017-3511",
    "CVE-2017-3526",
    "CVE-2017-3533",
    "CVE-2017-3539",
    "CVE-2017-3544",
    "CVE-2017-10053",
    "CVE-2017-10067",
    "CVE-2017-10074",
    "CVE-2017-10078",
    "CVE-2017-10081",
    "CVE-2017-10087",
    "CVE-2017-10089",
    "CVE-2017-10090",
    "CVE-2017-10096",
    "CVE-2017-10101",
    "CVE-2017-10102",
    "CVE-2017-10107",
    "CVE-2017-10108",
    "CVE-2017-10109",
    "CVE-2017-10110",
    "CVE-2017-10111",
    "CVE-2017-10115",
    "CVE-2017-10116",
    "CVE-2017-10135",
    "CVE-2017-10193",
    "CVE-2017-10198",
    "CVE-2017-10243"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : java-1.8.0-openjdk Multiple Vulnerabilities (NS-SA-2019-0111)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has java-1.8.0-openjdk packages installed that are affected by
multiple vulnerabilities:

  - It was found that the JAXP component of OpenJDK failed
    to correctly enforce parse tree size limits when parsing
    XML document. An attacker able to make a Java
    application parse a specially crafted XML document could
    use this flaw to make it consume an excessive amount of
    CPU and memory. (CVE-2017-3526)

  - An untrusted library search path flaw was found in the
    JCE component of OpenJDK. A local attacker could
    possibly use this flaw to cause a Java application using
    JCE to load an attacker-controlled library and hence
    escalate their privileges. (CVE-2017-3511)

  - It was discovered that the HTTP client implementation in
    the Networking component of OpenJDK could cache and re-
    use an NTLM authenticated connection in a different
    security context. A remote attacker could possibly use
    this flaw to make a Java application perform HTTP
    requests authenticated with credentials of a different
    user. (CVE-2017-3509)

  - A newline injection flaw was discovered in the SMTP
    client implementation in the Networking component in
    OpenJDK. A remote attacker could possibly use this flaw
    to manipulate SMTP connections established by a Java
    application. (CVE-2017-3544)

  - It was discovered that the Security component of OpenJDK
    did not allow users to restrict the set of algorithms
    allowed for Jar integrity verification. This flaw could
    allow an attacker to modify content of the Jar file that
    used weak signing key or hash algorithm. (CVE-2017-3539)

  - A newline injection flaw was discovered in the FTP
    client implementation in the Networking component in
    OpenJDK. A remote attacker could possibly use this flaw
    to manipulate FTP connections established by a Java
    application. (CVE-2017-3533)

  - It was discovered that the Libraries component of
    OpenJDK accepted ECDSA signatures using non-canonical
    DER encoding. This could cause a Java application to
    accept signature in an incorrect format not accepted by
    other cryptographic tools. (CVE-2016-5546)

  - It was discovered that the Libraries component of
    OpenJDK did not validate the length of the object
    identifier read from the DER input before allocating
    memory to store the OID. An attacker able to make a Java
    application decode a specially crafted DER input could
    cause the application to consume an excessive amount of
    memory. (CVE-2016-5547)

  - A covert timing channel flaw was found in the DSA
    implementation in the Libraries component of OpenJDK. A
    remote attacker could possibly use this flaw to extract
    certain information about the used key via a timing side
    channel. (CVE-2016-5548)

  - It was discovered that the Networking component of
    OpenJDK failed to properly parse user info from the URL.
    A remote attacker could cause a Java application to
    incorrectly parse an attacker supplied URL and interpret
    it differently from other applications processing the
    same URL. (CVE-2016-5552)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Networking). Supported
    versions that are affected are Java SE: 6u131, 7u121 and
    8u112; Java SE Embedded: 8u111. Easily exploitable
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
    installed by an administrator). CVSS v3.0 Base Score 4.3
    (Confidentiality impacts). (CVE-2017-3231,
    CVE-2017-3261)

  - It was discovered that the RMI registry and DCG
    implementations in the RMI component of OpenJDK
    performed deserialization of untrusted inputs. A remote
    attacker could possibly use this flaw to execute
    arbitrary code with the privileges of RMI registry or a
    Java RMI application. (CVE-2017-3241)

  - It was discovered that the JAAS component of OpenJDK did
    not use the correct way to extract user DN from the
    result of the user search LDAP query. A specially
    crafted user LDAP entry could cause the application to
    use an incorrect DN. (CVE-2017-3252)

  - It was discovered that the 2D component of OpenJDK
    performed parsing of iTXt and zTXt PNG image chunks even
    when configured to ignore metadata. An attacker able to
    make a Java application parse a specially crafted PNG
    image could cause the application to consume an
    excessive amount of memory. (CVE-2017-3253)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Libraries). Supported
    versions that are affected are Java SE: 6u131, 7u121 and
    8u112; Java SE Embedded: 8u111. Easily exploitable
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
    installed by an administrator). CVSS v3.0 Base Score 9.6
    (Confidentiality, Integrity and Availability impacts).
    (CVE-2017-3272)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Hotspot). Supported
    versions that are affected are Java SE: 7u121 and 8u112;
    Java SE Embedded: 8u111. Easily exploitable
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
    installed by an administrator). CVSS v3.0 Base Score 9.6
    (Confidentiality, Integrity and Availability impacts).
    (CVE-2017-3289)

  - It was discovered that the Libraries component of
    OpenJDK did not restrict the set of algorithms used for
    JAR integrity verification. This flaw could allow an
    attacker to modify content of the JAR file that used
    weak signing key or hash algorithm. (CVE-2016-5542)

  - A flaw was found in the way the JMX component of OpenJDK
    handled classloaders. An untrusted Java application or
    applet could use this flaw to bypass certain Java
    sandbox restrictions. (CVE-2016-5554)

  - It was discovered that the Hotspot component of OpenJDK
    did not properly check received Java Debug Wire Protocol
    (JDWP) packets. An attacker could possibly use this flaw
    to send debugging commands to a Java program running
    with debugging enabled if they could make victim's
    browser send HTTP requests to the JDWP port of the
    debugged application. (CVE-2016-5573)

  - A flaw was found in the way the Networking component of
    OpenJDK handled HTTP proxy authentication. A Java
    application could possibly expose HTTPS server
    authentication credentials via a plain text network
    connection to an HTTP proxy if proxy asked for
    authentication. (CVE-2016-5597)

  - It was discovered that the Hotspot component of OpenJDK
    did not properly check arguments of the
    System.arraycopy() function in certain cases. An
    untrusted Java application or applet could use this flaw
    to corrupt virtual machine's memory and completely
    bypass Java sandbox restrictions. (CVE-2016-5582)

  - Unspecified vulnerability in Oracle Java SE 6u115,
    7u101, and 8u92; and Java SE Embedded 8u91 allows remote
    attackers to affect integrity via vectors related to
    CORBA. (CVE-2016-3458)

  - Unspecified vulnerability in Oracle Java SE 6u115,
    7u101, and 8u92; Java SE Embedded 8u91; and JRockit
    R28.3.10 allows remote attackers to affect availability
    via vectors related to JAXP, a different vulnerability
    than CVE-2016-3508. (CVE-2016-3500)

  - Unspecified vulnerability in Oracle Java SE 6u115,
    7u101, and 8u92; Java SE Embedded 8u91; and JRockit
    R28.3.10 allows remote attackers to affect availability
    via vectors related to JAXP, a different vulnerability
    than CVE-2016-3500. (CVE-2016-3508)

  - Unspecified vulnerability in Oracle Java SE 6u115,
    7u101, and 8u92 and Java SE Embedded 8u91 allows remote
    attackers to affect confidentiality via vectors related
    to Hotspot. (CVE-2016-3550)

  - Unspecified vulnerability in Oracle Java SE 8u92 and
    Java SE Embedded 8u91 allows remote attackers to affect
    confidentiality, integrity, and availability via vectors
    related to Hotspot. (CVE-2016-3587)

  - Unspecified vulnerability in Oracle Java SE 8u92 and
    Java SE Embedded 8u91 allows remote attackers to affect
    confidentiality, integrity, and availability via vectors
    related to Libraries, a different vulnerability than
    CVE-2016-3610. (CVE-2016-3598)

  - Unspecified vulnerability in Oracle Java SE 7u101 and
    8u92 and Java SE Embedded 8u91 allows remote attackers
    to affect confidentiality, integrity, and availability
    via vectors related to Hotspot. (CVE-2016-3606)

  - Unspecified vulnerability in Oracle Java SE 8u92 and
    Java SE Embedded 8u91 allows remote attackers to affect
    confidentiality, integrity, and availability via vectors
    related to Libraries, a different vulnerability than
    CVE-2016-3598. (CVE-2016-3610)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Libraries). The
    supported version that is affected is Java SE: 8u131;
    Java SE Embedded: 8u131. Easily exploitable
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
    (CVE-2017-10111)

  - It was discovered that the Nashorn JavaScript engine in
    the Scripting component of OpenJDK could allow scripts
    to access Java APIs even when access to Java APIs was
    disabled. An untrusted JavaScript executed by Nashorn
    could use this flaw to bypass intended restrictions.
    (CVE-2017-10078)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Hotspot). Supported
    versions that are affected are Java SE: 6u151, 7u141 and
    8u131; Java SE Embedded: 8u131. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks require human
    interaction from a person other than the attacker.
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
    installed by an administrator). CVSS 3.0 Base Score 4.3
    (Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N).
    (CVE-2017-10081)

  - It was discovered that the JPEGImageReader
    implementation in the 2D component of OpenJDK would, in
    certain cases, read all image data even if it was not
    used later. A specially crafted image could cause a Java
    application to temporarily use an excessive amount of
    CPU and memory. (CVE-2017-10053)

  - Vulnerability in the Java SE component of Oracle Java SE
    (subcomponent: Security). Supported versions that are
    affected are Java SE: 6u151, 7u141 and 8u131. Difficult
    to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE. Successful attacks require human interaction
    from a person other than the attacker. Successful
    attacks of this vulnerability can result in takeover of
    Java SE. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that
    load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security.
    This vulnerability does not apply to Java deployments,
    typically in servers, that load and run only trusted
    code (e.g., code installed by an administrator). CVSS
    3.0 Base Score 7.5 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H).
    (CVE-2017-10067)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: RMI). Supported
    versions that are affected are Java SE: 6u151, 7u141 and
    8u131; Java SE Embedded: 8u131. Easily exploitable
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
    (CVE-2017-10107)

  - Vulnerability in the Java SE component of Oracle Java SE
    (subcomponent: ImageIO). Supported versions that are
    affected are Java SE: 6u151, 7u141 and 8u131. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Java SE. Successful attacks require human
    interaction from a person other than the attacker and
    while the vulnerability is in Java SE, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in takeover of
    Java SE. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that
    load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security.
    This vulnerability does not apply to Java deployments,
    typically in servers, that load and run only trusted
    code (e.g., code installed by an administrator). CVSS
    3.0 Base Score 9.6 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H).
    (CVE-2017-10089)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Libraries). Supported
    versions that are affected are Java SE: 6u151, 7u141 and
    8u131; Java SE Embedded: 8u131. Easily exploitable
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
    (CVE-2017-10087)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent:
    Serialization). Supported versions that are affected are
    Java SE: 6u151, 7u141 and 8u131; Java SE Embedded:
    8u131; JRockit: R28.3.14. Easily exploitable
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
    (CVE-2017-10108)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit
    component of Oracle Java SE (subcomponent:
    Serialization). Supported versions that are affected are
    Java SE: 6u151, 7u141 and 8u131; Java SE Embedded:
    8u131; JRockit: R28.3.14. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded, JRockit. Successful attacks of
    this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded, JRockit. Note: This vulnerability
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
    (CVE-2017-10109)

  - A covert timing channel flaw was found in the DSA
    implementation in the JCE component of OpenJDK. A remote
    attacker able to make a Java application generate DSA
    signatures on demand could possibly use this flaw to
    extract certain information about the used key via a
    timing side channel. (CVE-2017-10115)

  - A covert timing channel flaw was found in the PKCS#8
    implementation in the JCE component of OpenJDK. A remote
    attacker able to make a Java application repeatedly
    compare PKCS#8 key against an attacker controlled value
    could possibly use this flaw to determine the key via a
    timing side channel. (CVE-2017-10135)

  - It was discovered that the Security component of OpenJDK
    could fail to properly enforce restrictions defined for
    processing of X.509 certificate chains. A remote
    attacker could possibly use this flaw to make Java
    accept certificate using one of the disabled algorithms.
    (CVE-2017-10198)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: JAXP). Supported
    versions that are affected are Java SE: 6u151, 7u141 and
    8u131; Java SE Embedded: 8u131. Easily exploitable
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
    (CVE-2017-10101, CVE-2017-10096)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Hotspot). Supported
    versions that are affected are Java SE: 6u151, 7u141 and
    8u131; Java SE Embedded: 8u131. Difficult to exploit
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
    installed by an administrator). CVSS 3.0 Base Score 8.3
    (Confidentiality, Integrity and Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).
    (CVE-2017-10074)

  - Vulnerability in the Java SE component of Oracle Java SE
    (subcomponent: AWT). Supported versions that are
    affected are Java SE: 6u151, 7u141 and 8u131. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Java SE. Successful attacks require human
    interaction from a person other than the attacker and
    while the vulnerability is in Java SE, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in takeover of
    Java SE. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that
    load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security.
    This vulnerability does not apply to Java deployments,
    typically in servers, that load and run only trusted
    code (e.g., code installed by an administrator). CVSS
    3.0 Base Score 9.6 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H).
    (CVE-2017-10110)

  - It was discovered that the wsdlimport tool in the JAX-WS
    component of OpenJDK did not use secure XML parser
    settings when parsing WSDL XML documents. A specially
    crafted WSDL document could cause wsdlimport to use an
    excessive amount of CPU and memory, open connections to
    other hosts, or leak information. (CVE-2017-10243)

  - It was discovered that the DCG implementation in the RMI
    component of OpenJDK failed to correctly handle
    references. A remote attacker could possibly use this
    flaw to execute arbitrary code with the privileges of
    RMI registry or a Java RMI application. (CVE-2017-10102)

  - It was discovered that the LDAPCertStore class in the
    Security component of OpenJDK followed LDAP referrals to
    arbitrary URLs. A specially crafted LDAP referral URL
    could cause LDAPCertStore to communicate with non-LDAP
    servers. (CVE-2017-10116)

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
    of Oracle Java SE (subcomponent: Libraries). Supported
    versions that are affected are Java SE: 7u141 and 8u131;
    Java SE Embedded: 8u131. Easily exploitable
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
    (CVE-2017-10090)

  - The Type_MLU_Read function in cmstypes.c in Little CMS
    (aka lcms2) allows remote attackers to obtain sensitive
    information or cause a denial of service via an image
    with a crafted ICC profile, which triggers an out-of-
    bounds heap read. (CVE-2016-10165)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0111");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL java-1.8.0-openjdk packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5582");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/21");
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
    "java-1.8.0-openjdk-1.8.0.141-2.b16.el6_9",
    "java-1.8.0-openjdk-devel-1.8.0.141-2.b16.el6_9",
    "java-1.8.0-openjdk-headless-1.8.0.141-2.b16.el6_9"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk");
}
