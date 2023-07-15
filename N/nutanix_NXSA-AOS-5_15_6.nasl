#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164567);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2019-18282",
    "CVE-2019-19532",
    "CVE-2019-25013",
    "CVE-2020-0427",
    "CVE-2020-1971",
    "CVE-2020-7053",
    "CVE-2020-8625",
    "CVE-2020-10029",
    "CVE-2020-10543",
    "CVE-2020-10769",
    "CVE-2020-10878",
    "CVE-2020-12723",
    "CVE-2020-14314",
    "CVE-2020-14351",
    "CVE-2020-14385",
    "CVE-2020-14779",
    "CVE-2020-14781",
    "CVE-2020-14782",
    "CVE-2020-14792",
    "CVE-2020-14796",
    "CVE-2020-14797",
    "CVE-2020-14803",
    "CVE-2020-15436",
    "CVE-2020-15862",
    "CVE-2020-24394",
    "CVE-2020-25211",
    "CVE-2020-25212",
    "CVE-2020-25643",
    "CVE-2020-25645",
    "CVE-2020-25656",
    "CVE-2020-25705",
    "CVE-2020-28374",
    "CVE-2020-29573",
    "CVE-2020-29661",
    "CVE-2020-35513",
    "CVE-2021-2161",
    "CVE-2021-2163",
    "CVE-2021-3156",
    "CVE-2021-20265",
    "CVE-2021-20305",
    "CVE-2021-25122",
    "CVE-2021-25215",
    "CVE-2021-25329",
    "CVE-2021-26937",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/27");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.15.6)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.15.6. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.15.6 advisory.

  - The flow_dissector feature in the Linux kernel 4.3 through 5.x before 5.3.10 has a device tracking
    vulnerability, aka CID-55667441c84f. This occurs because the auto flowlabel of a UDP IPv6 packet relies on
    a 32-bit hashrnd value as a secret, and because jhash (instead of siphash) is used. The hashrnd value
    remains the same starting from boot time, and can be inferred by an attacker. This affects
    net/core/flow_dissector.c and related code. (CVE-2019-18282)

  - In the Linux kernel before 5.3.9, there are multiple out-of-bounds write bugs that can be caused by a
    malicious USB device in the Linux kernel HID drivers, aka CID-d9d4b1e46d95. This affects drivers/hid/hid-
    axff.c, drivers/hid/hid-dr.c, drivers/hid/hid-emsff.c, drivers/hid/hid-gaff.c, drivers/hid/hid-holtekff.c,
    drivers/hid/hid-lg2ff.c, drivers/hid/hid-lg3ff.c, drivers/hid/hid-lg4ff.c, drivers/hid/hid-lgff.c,
    drivers/hid/hid-logitech-hidpp.c, drivers/hid/hid-microsoft.c, drivers/hid/hid-sony.c, drivers/hid/hid-
    tmff.c, and drivers/hid/hid-zpff.c. (CVE-2019-19532)

  - The iconv feature in the GNU C Library (aka glibc or libc6) through 2.32, when processing invalid multi-
    byte input sequences in the EUC-KR encoding, may have a buffer over-read. (CVE-2019-25013)

  - In create_pinctrl of core.c, there is a possible out of bounds read due to a use after free. This could
    lead to local information disclosure with no additional execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-140550171
    (CVE-2020-0427)

  - The GNU C Library (aka glibc or libc6) before 2.32 could overflow an on-stack buffer during range
    reduction if an input to an 80-bit long double function contains a non-canonical bit pattern, a seen when
    passing a 0x5d414141414141410000 value to sinl on x86 targets. This is related to
    sysdeps/ieee754/ldbl-96/e_rem_pio2l.c. (CVE-2020-10029)

  - Perl before 5.30.3 on 32-bit platforms allows a heap-based buffer overflow because nested regular
    expression quantifiers have an integer overflow. (CVE-2020-10543)

  - A buffer over-read flaw was found in RH kernel versions before 5.0 in crypto_authenc_extractkeys in
    crypto/authenc.c in the IPsec Cryptographic algorithm's module, authenc. When a payload longer than 4
    bytes, and is not following 4-byte alignment boundary guidelines, it causes a buffer over-read threat,
    leading to a system crash. This flaw allows a local attacker with user privileges to cause a denial of
    service. (CVE-2020-10769)

  - Perl before 5.30.3 has an integer overflow related to mishandling of a PL_regkind[OP(n)] == NOTHING
    situation. A crafted regular expression could lead to malformed bytecode with a possibility of instruction
    injection. (CVE-2020-10878)

  - regcomp.c in Perl before 5.30.3 allows a buffer overflow via a crafted regular expression because of
    recursive S_study_chunk calls. (CVE-2020-12723)

  - A memory out-of-bounds read flaw was found in the Linux kernel before 5.9-rc2 with the ext3/ext4 file
    system, in the way it accesses a directory with broken indexing. This flaw allows a local user to crash
    the system if the directory exists. The highest threat from this vulnerability is to system availability.
    (CVE-2020-14314)

  - A flaw was found in the Linux kernel. A use-after-free memory flaw was found in the perf subsystem
    allowing a local attacker with permission to monitor perf events to corrupt memory and possibly escalate
    privileges. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2020-14351)

  - A flaw was found in the Linux kernel before 5.9-rc4. A failure of the file system metadata validator in
    XFS can cause an inode with a valid, user-creatable extended attribute to be flagged as corrupt. This can
    lead to the filesystem being shutdown, or otherwise rendered inaccessible until it is remounted, leading
    to a denial of service. The highest threat from this vulnerability is to system availability.
    (CVE-2020-14385)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Serialization).
    Supported versions that are affected are Java SE: 7u271, 8u261, 11.0.8 and 15; Java SE Embedded: 8u261.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: Applies to client and server deployment of Java. This vulnerability can be exploited through
    sandboxed Java Web Start applications and sandboxed Java applets. It can also be exploited by supplying
    data to APIs in the specified Component without using sandboxed Java Web Start applications or sandboxed
    Java applets, such as through a web service. (CVE-2020-14779)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: JNDI). Supported
    versions that are affected are Java SE: 7u271, 8u261, 11.0.8 and 15; Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of Java SE, Java SE Embedded accessible data. Note: Applies to client and server
    deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web
    service. (CVE-2020-14781)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 7u271, 8u261, 11.0.8 and 15; Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data. Note: Applies to
    client and server deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start
    applications and sandboxed Java applets. It can also be exploited by supplying data to APIs in the
    specified Component without using sandboxed Java Web Start applications or sandboxed Java applets, such as
    through a web service. (CVE-2020-14782, CVE-2020-14797)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Hotspot). Supported
    versions that are affected are Java SE: 7u271, 8u261, 11.0.8 and 15; Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker. Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Java SE, Java SE Embedded accessible data as well as unauthorized read access to
    a subset of Java SE, Java SE Embedded accessible data. Note: Applies to client and server deployment of
    Java. This vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java
    applets. It can also be exploited by supplying data to APIs in the specified Component without using
    sandboxed Java Web Start applications or sandboxed Java applets, such as through a web service.
    (CVE-2020-14792)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 7u271, 8u261, 11.0.8 and 15; Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker. Successful attacks of this vulnerability can result in unauthorized read access to a
    subset of Java SE, Java SE Embedded accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). (CVE-2020-14796)

  - Vulnerability in the Java SE product of Oracle Java SE (component: Libraries). Supported versions that are
    affected are Java SE: 11.0.8 and 15. Easily exploitable vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE. Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of Java SE accessible data. Note: This vulnerability
    applies to Java deployments, typically in clients running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in
    servers, that load and run only trusted code (e.g., code installed by an administrator). (CVE-2020-14803)

  - Use-after-free vulnerability in fs/block_dev.c in the Linux kernel before 5.8 allows local users to gain
    privileges or cause a denial of service by leveraging improper access to a certain error field.
    (CVE-2020-15436)

  - Net-SNMP through 5.7.3 has Improper Privilege Management because SNMP WRITE access to the EXTEND MIB
    provides the ability to run arbitrary commands as root. (CVE-2020-15862)

  - The X.509 GeneralName type is a generic type for representing different types of names. One of those name
    types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different
    instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both
    GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a
    possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1)
    Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in
    an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp
    authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an
    attacker can control both items being compared then that attacker could trigger a crash. For example if
    the attacker can trick a client or server into checking a malicious certificate against a malicious CRL
    then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a
    certificate. This checking happens prior to the signatures on the certificate and CRL being verified.
    OpenSSL's s_server, s_client and verify tools have support for the -crl_download option which implements
    automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an
    unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of
    EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will
    accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue.
    Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected
    1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w). (CVE-2020-1971)

  - In the Linux kernel before 5.7.8, fs/nfsd/vfs.c (in the NFS server) can set incorrect permissions on new
    filesystem objects when the filesystem lacks ACL support, aka CID-22cf8419f131. This occurs because the
    current umask is not considered. (CVE-2020-24394)

  - In the Linux kernel through 5.8.7, local attackers able to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c, aka CID-1cc5ef91d2ff.
    (CVE-2020-25211)

  - A TOCTOU mismatch in the NFS client code in the Linux kernel before 5.8.3 could be used by local attackers
    to corrupt memory or possibly have unspecified other impact because a size check is in fs/nfs/nfs4proc.c
    instead of fs/nfs/nfs4xdr.c, aka CID-b4487b935452. (CVE-2020-25212)

  - A flaw was found in the HDLC_PPP module of the Linux kernel in versions before 5.9-rc7. Memory corruption
    and a read overflow is caused by improper input validation in the ppp_cp_parse_cr function which can cause
    the system to crash or cause a denial of service. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25643)

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

  - In drivers/target/target_core_xcopy.c in the Linux kernel before 5.10.7, insufficient identifier checking
    in the LIO SCSI target code can be used by remote attackers to read or write files via directory traversal
    in an XCOPY request, aka CID-2896c93811e3. For example, an attack can occur over a network if the attacker
    has access to one iSCSI LUN. The attacker gains control over file access because I/O operations are
    proxied via an attacker-selected backstore. (CVE-2020-28374)

  - sysdeps/i386/ldbl2mpn.c in the GNU C Library (aka glibc or libc6) before 2.23 on x86 targets has a stack-
    based buffer overflow if the input to any of the printf family of functions is an 80-bit long double with
    a non-canonical bit pattern, as seen when passing a \x00\x04\x00\x00\x00\x00\x00\x00\x00\x04 value to
    sprintf. NOTE: the issue does not affect glibc by default in 2016 or later (i.e., 2.23 or later) because
    of commits made in 2015 for inlining of C99 math functions through use of GCC built-ins. In other words,
    the reference to 2.23 is intentional despite the mention of Fixed for glibc 2.33 in the 26649 reference.
    (CVE-2020-29573)

  - A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.
    (CVE-2020-29661)

  - A flaw incorrect umask during file or directory modification in the Linux kernel NFS (network file system)
    functionality was found in the way user create and delete object using NFSv4.2 or newer if both
    simultaneously accessing the NFS by the other process that is not using new NFSv4.2. A user with access to
    the NFS could use this flaw to starve the resources causing denial of service. (CVE-2020-35513)

  - In the Linux kernel 4.14 longterm through 4.14.165 and 4.19 longterm through 4.19.96 (and 5.x before 5.2),
    there is a use-after-free (write) in the i915_ppgtt_close function in drivers/gpu/drm/i915/i915_gem_gtt.c,
    aka CID-7dc40713618c. This is related to i915_gem_context_destroy_ioctl in
    drivers/gpu/drm/i915/i915_gem_context.c. (CVE-2020-7053)

  - BIND servers are vulnerable if they are running an affected version and are configured to use GSS-TSIG
    features. In a configuration which uses BIND's default settings the vulnerable code path is not exposed,
    but a server can be rendered vulnerable by explicitly setting valid values for the tkey-gssapi-keytab or
    tkey-gssapi-credentialconfiguration options. Although the default configuration is not vulnerable, GSS-
    TSIG is frequently used in networks where BIND is integrated with Samba, as well as in mixed-server
    environments that combine BIND servers with Active Directory domain controllers. The most likely outcome
    of a successful exploitation of the vulnerability is a crash of the named process. However, remote code
    execution, while unproven, is theoretically possible. Affects: BIND 9.5.0 -> 9.11.27, 9.12.0 -> 9.16.11,
    and versions BIND 9.11.3-S1 -> 9.11.27-S1 and 9.16.8-S1 -> 9.16.11-S1 of BIND Supported Preview Edition.
    Also release versions 9.17.0 -> 9.17.1 of the BIND 9.17 development branch (CVE-2020-8625)

  - A flaw was found in the way memory resources were freed in the unix_stream_recvmsg function in the Linux
    kernel when a signal was pending. This flaw allows an unprivileged local user to crash the system by
    exhausting available memory. The highest threat from this vulnerability is to system availability.
    (CVE-2021-20265)

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

  - When responding to new h2c connection requests, Apache Tomcat versions 10.0.0-M1 to 10.0.0, 9.0.0.M1 to
    9.0.41 and 8.5.0 to 8.5.61 could duplicate request headers and a limited amount of request body from one
    request to another meaning user A and user B could both see the results of user A's request.
    (CVE-2021-25122)

  - In BIND 9.0.0 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and 9.16.8-S1 ->
    9.16.13-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11 of the BIND
    9.17 development branch, when a vulnerable version of named receives a query for a record triggering the
    flaw described above, the named process will terminate due to a failed assertion check. The vulnerability
    affects all currently maintained BIND 9 branches (9.11, 9.11-S, 9.16, 9.16-S, 9.17) as well as all other
    versions of BIND 9. (CVE-2021-25215)

  - The fix for CVE-2020-9484 was incomplete. When using Apache Tomcat 10.0.0-M1 to 10.0.0, 9.0.0.M1 to
    9.0.41, 8.5.0 to 8.5.61 or 7.0.0. to 7.0.107 with a configuration edge case that was highly unlikely to be
    used, the Tomcat instance was still vulnerable to CVE-2020-9494. Note that both the previously published
    prerequisites for CVE-2020-9484 and the previously published mitigations for CVE-2020-9484 also apply to
    this issue. (CVE-2021-25329)

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

  - Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which
    allows privilege escalation to root via sudoedit -s and a command-line argument that ends with a single
    backslash character. (CVE-2021-3156)

  - A heap-based buffer overflow was found in the way sudo parses command line arguments. This flaw is
    exploitable by any local user who can execute the sudo command without authentication. Successful
    exploitation of this flaw could lead to privilege escalation.  (CVE-2021-3156)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.15.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1675021c");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26937");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sudo Heap-Based Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
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
  { 'fixed_version' : '5.15.6', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.15.6 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '5.15.6', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.15.6 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
