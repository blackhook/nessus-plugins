#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0022. The text
# itself is copyright (C) ZTE, Inc.


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134409);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2019-2745",
    "CVE-2019-2762",
    "CVE-2019-2769",
    "CVE-2019-2786",
    "CVE-2019-2816",
    "CVE-2019-2842",
    "CVE-2019-2945",
    "CVE-2019-2949",
    "CVE-2019-2962",
    "CVE-2019-2964",
    "CVE-2019-2973",
    "CVE-2019-2975",
    "CVE-2019-2978",
    "CVE-2019-2981",
    "CVE-2019-2983",
    "CVE-2019-2987",
    "CVE-2019-2988",
    "CVE-2019-2989",
    "CVE-2019-2992",
    "CVE-2019-2999",
    "CVE-2020-2583",
    "CVE-2020-2590",
    "CVE-2020-2593",
    "CVE-2020-2601",
    "CVE-2020-2604",
    "CVE-2020-2654",
    "CVE-2020-2659"
  );
  script_bugtraq_id(
    109185,
    109186,
    109187,
    109188,
    109201,
    109206
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : java-1.8.0-openjdk Multiple Vulnerabilities (NS-SA-2020-0022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has java-1.8.0-openjdk packages installed that are affected by
multiple vulnerabilities:

  - Vulnerability in the Java SE component of Oracle Java SE
    (subcomponent: JCE). The supported version that is
    affected is Java SE: 8u212. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE. Successful attacks of this vulnerability can result
    in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE. Note: This
    vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which
    supplies data to the APIs. CVSS 3.0 Base Score 3.7
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2019-2842)

  - Vulnerability in the Java SE component of Oracle Java SE
    (subcomponent: Security). Supported versions that are
    affected are Java SE: 7u221, 8u212 and 11.0.3. Difficult
    to exploit vulnerability allows unauthenticated attacker
    with logon to the infrastructure where Java SE executes
    to compromise Java SE. Successful attacks of this
    vulnerability can result in unauthorized access to
    critical data or complete access to all Java SE
    accessible data. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed
    Java Web Start applications or sandboxed Java applets
    (in Java SE 8), that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the
    APIs. CVSS 3.0 Base Score 5.1 (Confidentiality impacts).
    CVSS Vector:
    (CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N).
    (CVE-2019-2745)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Utilities). Supported
    versions that are affected are Java SE: 7u221, 8u212,
    11.0.3 and 12.0.1; Java SE Embedded: 8u211. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a partial denial of service (partial DOS) of
    Java SE, Java SE Embedded. Note: This vulnerability
    applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which
    supplies data to the APIs. CVSS 3.0 Base Score 5.3
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2019-2762, CVE-2019-2769)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Networking). Supported
    versions that are affected are Java SE: 7u221, 8u212,
    11.0.3 and 12.0.1; Java SE Embedded: 8u211. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Java SE, Java SE Embedded
    accessible data as well as unauthorized read access to a
    subset of Java SE, Java SE Embedded accessible data.
    Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8),
    that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by
    using APIs in the specified Component, e.g., through a
    web service which supplies data to the APIs. CVSS 3.0
    Base Score 4.8 (Confidentiality and Integrity impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).
    (CVE-2019-2816)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Security). Supported
    versions that are affected are Java SE: 8u212, 11.0.3
    and 12.0.1; Java SE Embedded: 8u211. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks require
    human interaction from a person other than the attacker
    and while the vulnerability is in Java SE, Java SE
    Embedded, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of Java
    SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which
    supplies data to the APIs. CVSS 3.0 Base Score 3.4
    (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N).
    (CVE-2019-2786)

  - Vulnerability in the Java SE product of Oracle Java SE
    (component: 2D). Supported versions that are affected
    are Java SE: 11.0.4 and 13. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE. Successful attacks of this vulnerability can result
    in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE. Note: This
    vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which
    supplies data to the APIs. CVSS 3.0 Base Score 3.7
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2019-2987)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Kerberos). Supported
    versions that are affected are Java SE: 7u231, 8u221,
    11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via Kerberos to compromise Java SE,
    Java SE Embedded. While the vulnerability is in Java SE,
    Java SE Embedded, attacks may significantly impact
    additional products. Successful attacks of this
    vulnerability can result in unauthorized access to
    critical data or complete access to all Java SE, Java SE
    Embedded accessible data. Note: This vulnerability
    applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which
    supplies data to the APIs. CVSS 3.0 Base Score 6.8
    (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N).
    (CVE-2019-2949)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: JAXP). Supported versions
    that are affected are Java SE: 7u231, 8u221, 11.0.4 and
    13; Java SE Embedded: 8u221. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets (in Java SE 8), that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability can
    also be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies
    data to the APIs. CVSS 3.0 Base Score 3.7 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2019-2973, CVE-2019-2981)

  - Vulnerability in the Java SE product of Oracle Java SE
    (component: Javadoc). Supported versions that are
    affected are Java SE: 7u231, 8u221, 11.0.4 and 13.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. Successful
    attacks require human interaction from a person other
    than the attacker and while the vulnerability is in Java
    SE, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access
    to some of Java SE accessible data as well as
    unauthorized read access to a subset of Java SE
    accessible data. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed
    Java Web Start applications or sandboxed Java applets
    (in Java SE 8), that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply
    to Java deployments, typically in servers, that load and
    run only trusted code (e.g., code installed by an
    administrator). CVSS 3.0 Base Score 4.7 (Confidentiality
    and Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N).
    (CVE-2019-2999)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: 2D). Supported versions
    that are affected are Java SE: 7u231, 8u221, 11.0.4 and
    13; Java SE Embedded: 8u221. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets (in Java SE 8), that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability does
    not apply to Java deployments, typically in servers,
    that load and run only trusted code (e.g., code
    installed by an administrator). CVSS 3.0 Base Score 3.7
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2019-2988, CVE-2019-2992)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Networking). Supported
    versions that are affected are Java SE: 7u231, 8u221,
    11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets (in Java SE 8), that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability can
    also be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies
    data to the APIs. CVSS 3.0 Base Score 3.7 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2019-2978)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Serialization). Supported
    versions that are affected are Java SE: 7u231, 8u221,
    11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets (in Java SE 8), that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability can
    also be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies
    data to the APIs. CVSS 3.0 Base Score 3.7 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2019-2983)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: 2D). Supported versions
    that are affected are Java SE: 7u231, 8u221, 11.0.4 and
    13; Java SE Embedded: 8u221. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets (in Java SE 8), that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability can
    also be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies
    data to the APIs. CVSS 3.0 Base Score 3.7 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2019-2962)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Networking). Supported
    versions that are affected are Java SE: 7u231, 8u221,
    11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks require
    human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8),
    that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an
    administrator). CVSS 3.0 Base Score 3.1 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L).
    (CVE-2019-2945)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Concurrency). Supported
    versions that are affected are Java SE: 7u231, 8u221,
    11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability can only
    be exploited by supplying data to APIs in the specified
    Component without using Untrusted Java Web Start
    applications or Untrusted Java applets, such as through
    a web service. CVSS 3.0 Base Score 3.7 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2019-2964)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Networking). Supported
    versions that are affected are Java SE: 7u231, 8u221,
    11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. While the vulnerability is in
    Java SE, Java SE Embedded, attacks may significantly
    impact additional products. Successful attacks of this
    vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all
    Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which
    supplies data to the APIs. CVSS v3.0 Base Score 6.8
    (Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N).
    (CVE-2019-2989)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Scripting). Supported
    versions that are affected are Java SE: 8u221, 11.0.4
    and 13; Java SE Embedded: 8u221. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Java SE, Java SE Embedded
    accessible data and unauthorized ability to cause a
    partial denial of service (partial DOS) of Java SE, Java
    SE Embedded. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets (in
    Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the
    APIs. CVSS 3.0 Base Score 4.8 (Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L).
    (CVE-2019-2975)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u241, 8u231,
    11.0.5 and 13.0.1; Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via Kerberos to compromise Java SE,
    Java SE Embedded. While the vulnerability is in Java SE,
    Java SE Embedded, attacks may significantly impact
    additional products. Successful attacks of this
    vulnerability can result in unauthorized access to
    critical data or complete access to all Java SE, Java SE
    Embedded accessible data. Note: This vulnerability
    applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which
    supplies data to the APIs. CVSS 3.0 Base Score 6.8
    (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N).
    (CVE-2020-2601)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Serialization). Supported
    versions that are affected are Java SE: 7u241, 8u231,
    11.0.5 and 13.0.1; Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets (in Java SE 8), that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability can
    also be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies
    data to the APIs. CVSS 3.0 Base Score 3.7 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2020-2583)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u241, 8u231,
    11.0.5 and 13.0.1; Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via Kerberos to compromise Java SE,
    Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Java SE, Java SE Embedded
    accessible data. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed
    Java Web Start applications or sandboxed Java applets
    (in Java SE 8), that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the
    APIs. CVSS 3.0 Base Score 3.7 (Integrity impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N).
    (CVE-2020-2590)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Networking). Supported
    versions that are affected are Java SE: 7u241, 8u231,
    11.0.5 and 13.0.1; Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Java SE, Java SE Embedded
    accessible data as well as unauthorized read access to a
    subset of Java SE, Java SE Embedded accessible data.
    Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8),
    that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by
    using APIs in the specified Component, e.g., through a
    web service which supplies data to the APIs. CVSS 3.0
    Base Score 4.8 (Confidentiality and Integrity impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).
    (CVE-2020-2593)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Serialization). Supported
    versions that are affected are Java SE: 7u241, 8u231,
    11.0.5 and 13.0.1; Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in takeover of Java SE, Java SE
    Embedded. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets (in
    Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the
    APIs. CVSS v3.0 Base Score 8.1 (Confidentiality,
    Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).
    (CVE-2020-2604)

  - Vulnerability in the Java SE product of Oracle Java SE
    (component: Libraries). Supported versions that are
    affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. Successful
    attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial
    DOS) of Java SE. Note: This vulnerability can only be
    exploited by supplying data to APIs in the specified
    Component without using Untrusted Java Web Start
    applications or Untrusted Java applets, such as through
    a web service. CVSS 3.0 Base Score 3.7 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2020-2654)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Networking). Supported
    versions that are affected are Java SE: 7u241 and 8u231;
    Java SE Embedded: 8u231. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets (in Java SE 8), that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability can
    also be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies
    data to the APIs. CVSS 3.0 Base Score 3.7 (Availability
    impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2020-2659)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0022");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL java-1.8.0-openjdk packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "java-1.8.0-openjdk-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-debug-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-debuginfo-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-demo-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-demo-debug-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-devel-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-devel-debug-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-headless-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-headless-debug-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-javadoc-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-javadoc-debug-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-src-1.8.0.242.b07-1.el6_10",
    "java-1.8.0-openjdk-src-debug-1.8.0.242.b07-1.el6_10"
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
