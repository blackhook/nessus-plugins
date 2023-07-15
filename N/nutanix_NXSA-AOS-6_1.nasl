#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164603);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2016-4658",
    "CVE-2017-5715",
    "CVE-2017-5753",
    "CVE-2017-5754",
    "CVE-2019-19532",
    "CVE-2019-20934",
    "CVE-2020-0427",
    "CVE-2020-7053",
    "CVE-2020-11651",
    "CVE-2020-11652",
    "CVE-2020-11668",
    "CVE-2020-14351",
    "CVE-2020-25211",
    "CVE-2020-25645",
    "CVE-2020-25656",
    "CVE-2020-25705",
    "CVE-2020-27777",
    "CVE-2020-28374",
    "CVE-2020-29661",
    "CVE-2020-36385",
    "CVE-2021-2161",
    "CVE-2021-2163",
    "CVE-2021-2341",
    "CVE-2021-2369",
    "CVE-2021-2388",
    "CVE-2021-3653",
    "CVE-2021-3656",
    "CVE-2021-3715",
    "CVE-2021-4104",
    "CVE-2021-20265",
    "CVE-2021-20271",
    "CVE-2021-20305",
    "CVE-2021-22543",
    "CVE-2021-22555",
    "CVE-2021-23840",
    "CVE-2021-23841",
    "CVE-2021-25214",
    "CVE-2021-25215",
    "CVE-2021-26937",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-29154",
    "CVE-2021-29650",
    "CVE-2021-30640",
    "CVE-2021-32399",
    "CVE-2021-33033",
    "CVE-2021-33034",
    "CVE-2021-33037",
    "CVE-2021-33909",
    "CVE-2021-35550",
    "CVE-2021-35556",
    "CVE-2021-35559",
    "CVE-2021-35561",
    "CVE-2021-35564",
    "CVE-2021-35565",
    "CVE-2021-35567",
    "CVE-2021-35578",
    "CVE-2021-35586",
    "CVE-2021-35588",
    "CVE-2021-35603",
    "CVE-2021-37576",
    "CVE-2021-40438",
    "CVE-2021-41617",
    "CVE-2021-42340",
    "CVE-2021-42574",
    "CVE-2021-43527",
    "CVE-2021-44832"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");
  script_xref(name:"CEA-ID", value:"CEA-2020-0041");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.1)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.1. It is, therefore, affected by multiple vulnerabilities
as referenced in the NXSA-AOS-6.1 advisory.

  - xpointer.c in libxml2 before 2.9.5 (as used in Apple iOS before 10, OS X before 10.12, tvOS before 10, and
    watchOS before 3, and other products) does not forbid namespace nodes in XPointer ranges, which allows
    remote attackers to execute arbitrary code or cause a denial of service (use-after-free and memory
    corruption) via a crafted XML document. (CVE-2016-4658)

  - Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow
    unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.
    (CVE-2017-5715)

  - Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized
    disclosure of information to an attacker with local user access via a side-channel analysis.
    (CVE-2017-5753)

  - Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow
    unauthorized disclosure of information to an attacker with local user access via a side-channel analysis
    of the data cache. (CVE-2017-5754)

  - In the Linux kernel before 5.3.9, there are multiple out-of-bounds write bugs that can be caused by a
    malicious USB device in the Linux kernel HID drivers, aka CID-d9d4b1e46d95. This affects drivers/hid/hid-
    axff.c, drivers/hid/hid-dr.c, drivers/hid/hid-emsff.c, drivers/hid/hid-gaff.c, drivers/hid/hid-holtekff.c,
    drivers/hid/hid-lg2ff.c, drivers/hid/hid-lg3ff.c, drivers/hid/hid-lg4ff.c, drivers/hid/hid-lgff.c,
    drivers/hid/hid-logitech-hidpp.c, drivers/hid/hid-microsoft.c, drivers/hid/hid-sony.c, drivers/hid/hid-
    tmff.c, and drivers/hid/hid-zpff.c. (CVE-2019-19532)

  - An issue was discovered in the Linux kernel before 5.2.6. On NUMA systems, the Linux fair scheduler has a
    use-after-free in show_numa_stats() because NUMA fault statistics are inappropriately freed, aka
    CID-16d51a590a8c. (CVE-2019-20934)

  - In create_pinctrl of core.c, there is a possible out of bounds read due to a use after free. This could
    lead to local information disclosure with no additional execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-140550171
    (CVE-2020-0427)

  - An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process
    ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods
    without authentication. These methods can be used to retrieve user tokens from the salt master and/or run
    arbitrary commands on salt minions. (CVE-2020-11651)

  - An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process
    ClearFuncs class allows access to some methods that improperly sanitize paths. These methods allow
    arbitrary directory access to authenticated users. (CVE-2020-11652)

  - In the Linux kernel before 5.6.1, drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink camera USB
    driver) mishandles invalid descriptors, aka CID-a246b4d54770. (CVE-2020-11668)

  - A flaw was found in the Linux kernel. A use-after-free memory flaw was found in the perf subsystem
    allowing a local attacker with permission to monitor perf events to corrupt memory and possibly escalate
    privileges. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2020-14351)

  - In the Linux kernel through 5.8.7, local attackers able to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c, aka CID-1cc5ef91d2ff.
    (CVE-2020-25211)

  - A flaw was found in the Linux kernel in versions before 5.9-rc7. Traffic between two Geneve endpoints may
    be unencrypted when IPsec is configured to encrypt traffic for the specific UDP port used by the GENEVE
    tunnel allowing anyone between the two endpoints to read the traffic unencrypted. The main threat from
    this vulnerability is to data confidentiality. (CVE-2020-25645)

  - A flaw was found in the Linux kernel. A use-after-free was found in the way the console subsystem was
    using ioctls KDGKBSENT and KDSKBSENT. A local user could use this flaw to get read memory access out of
    bounds. The highest threat from this vulnerability is to data confidentiality. (CVE-2020-25656)

  - A flaw in ICMP packets in the Linux kernel may allow an attacker to quickly scan open UDP ports. This flaw
    allows an off-path remote attacker to effectively bypass source port UDP randomization. Software that
    relies on UDP source port randomization are indirectly affected as well on the Linux Based Products
    (RUGGEDCOM RM1224: All versions between v5.0 and v6.4, SCALANCE M-800: All versions between v5.0 and v6.4,
    SCALANCE S615: All versions between v5.0 and v6.4, SCALANCE SC-600: All versions prior to v2.1.3, SCALANCE
    W1750D: v8.3.0.1, v8.6.0, and v8.7.0, SIMATIC Cloud Connect 7: All versions, SIMATIC MV500 Family: All
    versions, SIMATIC NET CP 1243-1 (incl. SIPLUS variants): Versions 3.1.39 and later, SIMATIC NET CP 1243-7
    LTE EU: Version (CVE-2020-25705)

  - A flaw was found in the way RTAS handled memory accesses in userspace to kernel communication. On a locked
    down (usually due to Secure Boot) guest system running on top of PowerVM or KVM hypervisors (pseries
    platform) a root like local user could use this flaw to further increase their privileges to that of a
    running kernel. (CVE-2020-27777)

  - In drivers/target/target_core_xcopy.c in the Linux kernel before 5.10.7, insufficient identifier checking
    in the LIO SCSI target code can be used by remote attackers to read or write files via directory traversal
    in an XCOPY request, aka CID-2896c93811e3. For example, an attack can occur over a network if the attacker
    has access to one iSCSI LUN. The attacker gains control over file access because I/O operations are
    proxied via an attacker-selected backstore. (CVE-2020-28374)

  - A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.
    (CVE-2020-29661)

  - An issue was discovered in the Linux kernel before 5.10. drivers/infiniband/core/ucma.c has a use-after-
    free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is
    called, aka CID-f5449e74802c. (CVE-2020-36385)

  - In the Linux kernel 4.14 longterm through 4.14.165 and 4.19 longterm through 4.19.96 (and 5.x before 5.2),
    there is a use-after-free (write) in the i915_ppgtt_close function in drivers/gpu/drm/i915/i915_gem_gtt.c,
    aka CID-7dc40713618c. This is related to i915_gem_context_destroy_ioctl in
    drivers/gpu/drm/i915/i915_gem_context.c. (CVE-2020-7053)

  - A flaw was found in the way memory resources were freed in the unix_stream_recvmsg function in the Linux
    kernel when a signal was pending. This flaw allows an unprivileged local user to crash the system by
    exhausting available memory. The highest threat from this vulnerability is to system availability.
    (CVE-2021-20265)

  - A flaw was found in RPM's signature check functionality when reading a package file. This flaw allows an
    attacker who can convince a victim to install a seemingly verifiable package, whose signature header was
    modified, to cause RPM database corruption and execute code. The highest threat from this vulnerability is
    to data integrity, confidentiality, and system availability. (CVE-2021-20271)

  - A flaw was found in Nettle in versions before 3.7.2, where several Nettle signature verification functions
    (GOST DSA, EDDSA & ECDSA) result in the Elliptic Curve Cryptography point (ECC) multiply function being
    called with out-of-range scalers, possibly resulting in incorrect results. This flaw allows an attacker to
    force an invalid signature, causing an assertion failure or possible validation. The highest threat to
    this vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-20305)

  - Vulnerability in the Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition product of Oracle Java
    SE (component: Libraries). Supported versions that are affected are Java SE: 7u291, 8u281, 11.0.10, 16;
    Java SE Embedded: 8u281; Oracle GraalVM Enterprise Edition: 19.3.5, 20.3.1.2 and 21.0.0.2. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition. Successful attacks of this
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or all
    Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability
    applies to Java deployments that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. It can also be exploited by supplying untrusted data to APIs in the
    specified Component. (CVE-2021-2161)

  - Vulnerability in the Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition product of Oracle Java
    SE (component: Libraries). Supported versions that are affected are Java SE: 7u291, 8u281, 11.0.10, 16;
    Java SE Embedded: 8u281; Oracle GraalVM Enterprise Edition: 19.3.5, 20.3.1.2 and 21.0.0.2. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Java SE, Java SE Embedded,
    Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments
    that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox
    for security. (CVE-2021-2163)

  - An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass
    RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users
    with the ability to start and control a VM to read/write random pages of memory and can result in local
    privilege escalation. (CVE-2021-22543)

  - A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c.
    This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name
    space (CVE-2021-22555)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Networking). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle
    GraalVM Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise
    Edition. Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). (CVE-2021-2341)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Library). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.2 and 21.1.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). (CVE-2021-2369)

  - Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument
    in some cases where the input length is close to the maximum permissable length for an integer on the
    platform. In such cases the return value from the function call will be 1 (indicating success), but the
    output length value will be negative. This could cause applications to behave incorrectly or crash.
    OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to
    OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out
    of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should
    upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i).
    Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x). (CVE-2021-23840)

  - The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based
    on the issuer and serial number data contained within an X509 certificate. However it fails to correctly
    handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is
    maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a
    potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by
    OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on
    certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are
    affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x
    and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving
    public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should
    upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected
    1.0.2-1.0.2x). (CVE-2021-23841)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Hotspot). Supported versions that are affected are Java SE: 8u291, 11.0.11, 16.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in takeover of Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2021-2388)

  - In BIND 9.8.5 -> 9.8.8, 9.9.3 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and
    9.16.8-S1 -> 9.16.13-S1 of BIND 9 Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11
    of the BIND 9.17 development branch, when a vulnerable version of named receives a malformed IXFR
    triggering the flaw described above, the named process will terminate due to a failed assertion the next
    time the transferred secondary zone is refreshed. (CVE-2021-25214)

  - In BIND 9.0.0 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and 9.16.8-S1 ->
    9.16.13-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11 of the BIND
    9.17 development branch, when a vulnerable version of named receives a query for a record triggering the
    flaw described above, the named process will terminate due to a failed assertion check. The vulnerability
    affects all currently maintained BIND 9 branches (9.11, 9.11-S, 9.16, 9.16-S, 9.17) as well as all other
    versions of BIND 9. (CVE-2021-25215)

  - encoding.c in GNU Screen through 4.8.0 allows remote attackers to cause a denial of service (invalid write
    access and application crash) or possibly have unspecified other impact via a crafted UTF-8 character
    sequence. (CVE-2021-26937)

  - An issue was discovered in the Linux kernel through 5.11.3. A kernel pointer leak can be used to determine
    the address of the iscsi_transport structure. When an iSCSI transport is registered with the iSCSI
    subsystem, the transport's handle is available to unprivileged users via the sysfs file system, at
    /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When read, the show_transport_handle function (in
    drivers/scsi/scsi_transport_iscsi.c) is called, which leaks the handle. This handle is actually the
    pointer to an iscsi_transport struct in the kernel module's global variables. (CVE-2021-27363)

  - An issue was discovered in the Linux kernel through 5.11.3. drivers/scsi/scsi_transport_iscsi.c is
    adversely affected by the ability of an unprivileged user to craft Netlink messages. (CVE-2021-27364)

  - An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a
    Netlink message. (CVE-2021-27365)

  - BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements,
    allowing them to execute arbitrary code within the kernel context. This affects
    arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c. (CVE-2021-29154)

  - An issue was discovered in the Linux kernel before 5.11.11. The netfilter subsystem allows attackers to
    cause a denial of service (panic) because net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h
    lack a full memory barrier upon the assignment of a new table value, aka CID-175e476b8cdf.
    (CVE-2021-29650)

  - A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to authenticate using variations of
    a valid user name and/or to bypass some of the protection provided by the LockOut Realm. This issue
    affects Apache Tomcat 10.0.0-M1 to 10.0.5; 9.0.0.M1 to 9.0.45; 8.5.0 to 8.5.65. (CVE-2021-30640)

  - net/bluetooth/hci_request.c in the Linux kernel through 5.12.2 has a race condition for removal of the HCI
    controller. (CVE-2021-32399)

  - The Linux kernel before 5.11.14 has a use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c because
    the CIPSO and CALIPSO refcounting for the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads
    to writing an arbitrary value. (CVE-2021-33033)

  - In the Linux kernel before 5.12.4, net/bluetooth/hci_event.c has a use-after-free when destroying an
    hci_chan, aka CID-5c4c8c954409. This leads to writing an arbitrary value. (CVE-2021-33034)

  - Apache Tomcat 10.0.0-M1 to 10.0.6, 9.0.0.M1 to 9.0.46 and 8.5.0 to 8.5.66 did not correctly parse the HTTP
    transfer-encoding request header in some circumstances leading to the possibility to request smuggling
    when used with a reverse proxy. Specifically: - Tomcat incorrectly ignored the transfer encoding header if
    the client declared it would only accept an HTTP/1.0 response; - Tomcat honoured the identify encoding;
    and - Tomcat did not ensure that, if present, the chunked encoding was the final encoding.
    (CVE-2021-33037)

  - fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer
    allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an
    unprivileged user, aka CID-8cae8cd89f05. (CVE-2021-33909)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JSSE). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12; Oracle GraalVM Enterprise
    Edition: 20.3.3 and 21.2.0. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via TLS to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of
    this vulnerability can result in unauthorized access to critical data or complete access to all Java SE,
    Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through
    a web service which supplies data to the APIs. (CVE-2021-35550)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Swing). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that
    load and run only trusted code (e.g., code installed by an administrator). (CVE-2021-35556)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Swing). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. (CVE-2021-35559)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Utility). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. (CVE-2021-35561)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Keytool). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. (CVE-2021-35564)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JSSE). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12; Oracle GraalVM Enterprise
    Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via TLS to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying
    data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted
    Java applets, such as through a web service. (CVE-2021-35565)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Libraries). Supported versions that are affected are Java SE: 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows low privileged attacker
    with network access via Kerberos to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful
    attacks require human interaction from a person other than the attacker and while the vulnerability is in
    Java SE, Oracle GraalVM Enterprise Edition, attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies
    to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. (CVE-2021-35567)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JSSE). Supported versions that are affected are Java SE: 8u301, 11.0.12, 17; Oracle GraalVM Enterprise
    Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via TLS to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying
    data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted
    Java applets, such as through a web service. (CVE-2021-35578)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    ImageIO). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. (CVE-2021-35586)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Hotspot). Supported versions that are affected are Java SE: 7u311, 8u301; Oracle GraalVM Enterprise
    Edition: 20.3.3 and 21.2.0. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful
    attacks require human interaction from a person other than the attacker. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through
    a web service which supplies data to the APIs. (CVE-2021-35588)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JSSE). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via TLS to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks
    of this vulnerability can result in unauthorized read access to a subset of Java SE, Oracle GraalVM
    Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service
    which supplies data to the APIs. (CVE-2021-35603)

  - A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when
    processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested
    guest (L2). Due to improper validation of the int_ctl field, this issue could allow a malicious L1 to
    enable AVIC support (Advanced Virtual Interrupt Controller) for the L2 guest. As a result, the L2 guest
    would be allowed to read/write physical pages of the host, resulting in a crash of the entire system, leak
    of sensitive data or potential guest-to-host escape. This flaw affects Linux kernel versions prior to
    5.14-rc7. (CVE-2021-3653)

  - A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when
    processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested
    guest (L2). Due to improper validation of the virt_ext field, this issue could allow a malicious L1 to
    disable both VMLOAD/VMSAVE intercepts and VLS (Virtual VMLOAD/VMSAVE) for the L2 guest. As a result, the
    L2 guest would be allowed to read/write physical pages of the host, resulting in a crash of the entire
    system, leak of sensitive data or potential guest-to-host escape. (CVE-2021-3656)

  - A flaw was found in the Routing decision classifier in the Linux kernel's Traffic Control networking
    subsystem in the way it handled changing of classification filters, leading to a use-after-free condition.
    This flaw allows unprivileged local users to escalate their privileges on the system. The highest threat
    from this vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-3715)

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

  - A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the
    remote user. This issue affects Apache HTTP Server 2.4.48 and earlier. (CVE-2021-40438)

  - JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write
    access to the Log4j configuration. The attacker can provide TopicBindingName and
    TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result
    in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2
    when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of
    life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the
    previous versions. (CVE-2021-4104)

  - sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used, allows
    privilege escalation because supplemental groups are not initialized as expected. Helper programs for
    AuthorizedKeysCommand and AuthorizedPrincipalsCommand may run with privileges associated with group
    memberships of the sshd process, if the configuration specifies running the command as a different user.
    (CVE-2021-41617)

  - The fix for bug 63362 present in Apache Tomcat 10.1.0-M1 to 10.1.0-M5, 10.0.0-M1 to 10.0.11, 9.0.40 to
    9.0.53 and 8.5.60 to 8.5.71 introduced a memory leak. The object introduced to collect metrics for HTTP
    upgrade connections was not released for WebSocket connections once the connection was closed. This
    created a memory leak that, over time, could lead to a denial of service via an OutOfMemoryError.
    (CVE-2021-42340)

  - ** DISPUTED ** An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through
    14.0. It permits the visual reordering of characters via control sequences, which can be used to craft
    source code that renders different logic than the logical ordering of tokens ingested by compilers and
    interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such
    that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium
    offers the following alternative approach to presenting this concern. An issue is noted in the nature of
    international text that can affect applications that implement support for The Unicode Standard and the
    Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-
    right and right-to-left characters, the visual order of tokens may be different from their logical order.
    Additionally, control characters needed to fully support the requirements of bidirectional text can
    further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such
    that the ordering of tokens perceived by human reviewers does not match what will be processed by a
    compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its
    document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also
    provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode
    Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the
    BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading
    visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.
    (CVE-2021-42574)

  - NSS (Network Security Services) versions prior to 3.73 or 3.68.1 ESR are vulnerable to a heap overflow
    when handling DER-encoded DSA or RSA-PSS signatures. Applications using NSS for handling signatures
    encoded within CMS, S/MIME, PKCS \#7, or PKCS \#12 are likely to be impacted. Applications using NSS for
    certificate validation or other TLS, X.509, OCSP or CRL functionality may be impacted, depending on how
    they configure NSS. *Note: This vulnerability does NOT impact Mozilla Firefox.* However, email clients and
    PDF viewers that use NSS for signature verification, such as Thunderbird, LibreOffice, Evolution and
    Evince are believed to be impacted. This vulnerability affects NSS < 3.73 and NSS < 3.68.1.
    (CVE-2021-43527)

  - Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are
    vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI
    LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by
    limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.
    (CVE-2021-44832)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38a44d37");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4658");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-43527");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt Master/Minion Unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/10");
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
  { 'fixed_version' : '6.1', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.1 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '6.1', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.1 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
