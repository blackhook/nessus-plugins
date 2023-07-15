#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164601);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2019-17571",
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-9484",
    "CVE-2020-9488",
    "CVE-2020-25704",
    "CVE-2020-25709",
    "CVE-2020-25710",
    "CVE-2020-36322",
    "CVE-2020-36385",
    "CVE-2021-0920",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-3752",
    "CVE-2021-4034",
    "CVE-2021-4155",
    "CVE-2021-20271",
    "CVE-2021-21996",
    "CVE-2021-26691",
    "CVE-2021-34798",
    "CVE-2021-39275",
    "CVE-2021-41617",
    "CVE-2021-42739",
    "CVE-2021-43527",
    "CVE-2021-44790",
    "CVE-2021-45046",
    "CVE-2021-45105",
    "CVE-2021-45417",
    "CVE-2021-45960",
    "CVE-2021-46143",
    "CVE-2022-0330",
    "CVE-2022-0778",
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
    "CVE-2022-21349",
    "CVE-2022-21360",
    "CVE-2022-21365",
    "CVE-2022-21366",
    "CVE-2022-22720",
    "CVE-2022-22822",
    "CVE-2022-22823",
    "CVE-2022-22824",
    "CVE-2022-22825",
    "CVE-2022-22826",
    "CVE-2022-22827",
    "CVE-2022-22942",
    "CVE-2022-23181",
    "CVE-2022-23302",
    "CVE-2022-23305",
    "CVE-2022-23307",
    "CVE-2022-23852",
    "CVE-2022-24407",
    "CVE-2022-25235",
    "CVE-2022-25236",
    "CVE-2022-25315"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/22");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.20.4)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.20.4. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.20.4 advisory.

  - Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data
    which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when
    listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.
    (CVE-2019-17571)

  - In various methods of hid-multitouch.c, there is a possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege with no additional execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-162844689References: Upstream kernel (CVE-2020-0465)

  - In do_epoll_ctl and ep_loop_check_proc of eventpoll.c, there is a possible use after free due to a logic
    error. This could lead to local escalation of privilege with no additional execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-147802478References: Upstream kernel (CVE-2020-0466)

  - A flaw memory leak in the Linux kernel performance monitoring subsystem was found in the way if using
    PERF_EVENT_IOC_SET_FILTER. A local user could use this flaw to starve the resources causing denial of
    service. (CVE-2020-25704)

  - A flaw was found in OpenLDAP. This flaw allows an attacker who can send a malicious packet to be processed
    by OpenLDAP's slapd server, to trigger an assertion failure. The highest threat from this vulnerability is
    to system availability. (CVE-2020-25709)

  - A flaw was found in OpenLDAP in versions before 2.4.56. This flaw allows an attacker who sends a malicious
    packet processed by OpenLDAP to force a failed assertion in csnNormalize23(). The highest threat from this
    vulnerability is to system availability. (CVE-2020-25710)

  - An issue was discovered in the FUSE filesystem implementation in the Linux kernel before 5.10.6, aka
    CID-5d069dbe8aaf. fuse_do_getattr() calls make_bad_inode() in inappropriate situations, causing a system
    crash. NOTE: the original fix for this vulnerability was incomplete, and its incompleteness is tracked as
    CVE-2021-28950. (CVE-2020-36322)

  - An issue was discovered in the Linux kernel before 5.10. drivers/infiniband/core/ucma.c has a use-after-
    free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is
    called, aka CID-f5449e74802c. (CVE-2020-36385)

  - When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to
    7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the
    server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is
    configured with sessionAttributeValueClassNameFilter=null (the default unless a SecurityManager is used)
    or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker
    knows the relative file path from the storage location used by FileStore to the file the attacker has
    control over; then, using a specifically crafted request, the attacker will be able to trigger remote code
    execution via deserialization of the file under their control. Note that all of conditions a) to d) must
    be true for the attack to succeed. (CVE-2020-9484)

  - Improper validation of certificate with host mismatch in Apache Log4j SMTP appender. This could allow an
    SMTPS connection to be intercepted by a man-in-the-middle attack which could leak any log messages sent
    through that appender. Fixed in Apache Log4j 2.12.3 and 2.13.1 (CVE-2020-9488)

  - In unix_scm_to_skb of af_unix.c, there is a possible use after free bug due to a race condition. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-196926917References:
    Upstream kernel (CVE-2021-0920)

  - A flaw was found in RPM's signature check functionality when reading a package file. This flaw allows an
    attacker who can convince a victim to install a seemingly verifiable package, whose signature header was
    modified, to cause RPM database corruption and execute code. The highest threat from this vulnerability is
    to data integrity, confidentiality, and system availability. (CVE-2021-20271)

  - An issue was discovered in SaltStack Salt before 3003.3. A user who has control of the source, and
    source_hash URLs can gain full file system access as root on a salt minion. (CVE-2021-21996)

  - In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server
    could cause a heap overflow (CVE-2021-26691)

  - Malformed requests may cause the server to dereference a NULL pointer. This issue affects Apache HTTP
    Server 2.4.48 and earlier. (CVE-2021-34798)

  - A flaw double-free memory corruption in the Linux kernel HCI device initialization subsystem was found in
    the way user attach malicious HCI TTY Bluetooth device. A local user could use this flaw to crash the
    system. This flaw affects all the Linux kernel versions starting from 3.13. (CVE-2021-3564)

  - A use-after-free in function hci_sock_bound_ioctl() of the Linux kernel HCI subsystem was found in the way
    user calls ioct HCIUNBLOCKADDR or other way triggers race condition of the call hci_unregister_dev()
    together with one of the calls hci_sock_blacklist_add(), hci_sock_blacklist_del(), hci_get_conn_info(),
    hci_get_auth_info(). A privileged local user could use this flaw to crash the system or escalate their
    privileges on the system. This flaw affects the Linux kernel versions prior to 5.13-rc5. (CVE-2021-3573)

  - A use-after-free flaw was found in the Linux kernel's Bluetooth subsystem in the way user calls connect to
    the socket and disconnect simultaneously due to a race condition. This flaw allows a user to crash the
    system or escalate their privileges. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-3752)

  - ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules
    pass untrusted data to these functions, but third-party / external modules may. This issue affects Apache
    HTTP Server 2.4.48 and earlier. (CVE-2021-39275)

  - A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is
    a setuid tool designed to allow unprivileged users to run commands as privileged users according
    predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly
    and ends trying to execute environment variables as commands. An attacker can leverage this by crafting
    environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully
    executed the attack can cause a local privilege escalation given unprivileged users administrative rights
    on the target machine. (CVE-2021-4034)

  - A data leak flaw was found in the way XFS_IOC_ALLOCSP IOCTL in the XFS filesystem allowed for size
    increase of files with unaligned size. A local attacker could use this flaw to leak data on the XFS
    filesystem otherwise not accessible to them. (CVE-2021-4155)

  - sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used, allows
    privilege escalation because supplemental groups are not initialized as expected. Helper programs for
    AuthorizedKeysCommand and AuthorizedPrincipalsCommand may run with privileges associated with group
    memberships of the sshd process, if the configuration specifies running the command as a different user.
    (CVE-2021-41617)

  - A heap-based buffer overflow flaw was found in the Linux kernel FireDTV media card driver, where the user
    calls the CA_SEND_MSG ioctl. This flaw allows a local user of the host machine to crash the system or
    escalate privileges on the system. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-42739)

  - NSS (Network Security Services) versions prior to 3.73 or 3.68.1 ESR are vulnerable to a heap overflow
    when handling DER-encoded DSA or RSA-PSS signatures. Applications using NSS for handling signatures
    encoded within CMS, S/MIME, PKCS \#7, or PKCS \#12 are likely to be impacted. Applications using NSS for
    certificate validation or other TLS, X.509, OCSP or CRL functionality may be impacted, depending on how
    they configure NSS. *Note: This vulnerability does NOT impact Mozilla Firefox.* However, email clients and
    PDF viewers that use NSS for signature verification, such as Thunderbird, LibreOffice, Evolution and
    Evince are believed to be impacted. This vulnerability affects NSS < 3.73 and NSS < 3.68.1.
    (CVE-2021-43527)

  - A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser
    (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the
    vulnerability though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and
    earlier. (CVE-2021-44790)

  - It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-
    default configurations. This could allows attackers with control over Thread Context Map (MDC) input data
    when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for
    example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input
    data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some
    environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix
    this issue by removing support for message lookup patterns and disabling JNDI functionality by default.
    (CVE-2021-45046)

  - Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from
    uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread
    Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed
    in Log4j 2.17.0, 2.12.3, and 2.3.1. (CVE-2021-45105)

  - AIDE before 0.17.4 allows local users to obtain root privileges via crafted file metadata (such as XFS
    extended attributes or tmpfs ACLs), because of a heap-based buffer overflow. (CVE-2021-45417)

  - In Expat (aka libexpat) before 2.4.3, a left shift by 29 (or more) places in the storeAtts function in
    xmlparse.c can lead to realloc misbehavior (e.g., allocating too few bytes, or only freeing memory).
    (CVE-2021-45960)

  - In doProlog in xmlparse.c in Expat (aka libexpat) before 2.4.3, an integer overflow exists for
    m_groupSize. (CVE-2021-46143)

  - A random memory access flaw was found in the Linux kernel's GPU i915 kernel driver functionality in the
    way a user may run malicious code on the GPU. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-0330)

  - The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Serialization). Supported versions that are affected are Oracle Java SE: 7u321, 8u311,
    11.0.13, 17.01; Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible
    data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by
    using APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
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
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
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
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
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
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
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
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
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
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
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
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
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
    using APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21341)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: 2D). Supported versions that are affected are Oracle Java SE: 7u321, 8u311; Oracle GraalVM
    Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise
    Edition. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial
    denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21349)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: ImageIO). Supported versions that are affected are Oracle Java SE: 7u321, 8u311, 11.0.13,
    17.01; Oracle GraalVM Enterprise Edition: 20.3.4 and 21.3.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21360, CVE-2022-21365)

  - Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling (CVE-2022-22720)

  - addBinding in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22822)

  - build_model in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22823)

  - defineAttribute in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.
    (CVE-2022-22824)

  - lookup in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22825)

  - nextScaffoldPart in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.
    (CVE-2022-22826)

  - storeAtts in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22827)

  - The fix for bug CVE-2020-9484 introduced a time of check, time of use vulnerability into Apache Tomcat
    10.1.0-M1 to 10.1.0-M8, 10.0.0-M5 to 10.0.14, 9.0.35 to 9.0.56 and 8.5.55 to 8.5.73 that allowed a local
    attacker to perform actions with the privileges of the user that the Tomcat process is using. This issue
    is only exploitable when Tomcat is configured to persist sessions using the FileStore. (CVE-2022-23181)

  - JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when the attacker
    has write access to the Log4j configuration or if the configuration references an LDAP service the
    attacker has access to. The attacker can provide a TopicConnectionFactoryBindingName configuration causing
    JMSSink to perform JNDI requests that result in remote code execution in a similar fashion to
    CVE-2021-4104. Note this issue only affects Log4j 1.x when specifically configured to use JMSSink, which
    is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2
    as it addresses numerous other issues from the previous versions. (CVE-2022-23302)

  - By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the
    values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be
    included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or
    headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue
    only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default.
    Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized
    SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of
    life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the
    previous versions. (CVE-2022-23305)

  - CVE-2020-9493 identified a deserialization issue that was present in Apache Chainsaw. Prior to Chainsaw
    V2.0 Chainsaw was a component of Apache Log4j 1.2.x where the same issue exists. (CVE-2022-23307)

  - Expat (aka libexpat) before 2.4.4 has a signed integer overflow in XML_GetBuffer, for configurations with
    a nonzero XML_CONTEXT_BYTES. (CVE-2022-23852)

  - In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL
    INSERT or UPDATE statement. (CVE-2022-24407)

  - xmltok_impl.c in Expat (aka libexpat) before 2.4.5 lacks certain validation of encoding, such as checks
    for whether a UTF-8 character is valid in a certain context. (CVE-2022-25235)

  - xmlparse.c in Expat (aka libexpat) before 2.4.5 allows attackers to insert namespace-separator characters
    into namespace URIs. (CVE-2022-25236)

  - In Expat (aka libexpat) before 2.4.5, there is an integer overflow in storeRawNames. (CVE-2022-25315)

  - kernel: failing usercopy allows for use-after-free exploitation (CVE-2022-22942)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.20.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ace96a74");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23307");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-25315");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.20.4', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.20.4 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '5.20.4', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.20.4 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
