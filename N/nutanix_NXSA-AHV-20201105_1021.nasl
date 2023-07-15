#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164552);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2017-12652",
    "CVE-2018-20843",
    "CVE-2019-2974",
    "CVE-2019-5094",
    "CVE-2019-5188",
    "CVE-2019-5482",
    "CVE-2019-11719",
    "CVE-2019-11727",
    "CVE-2019-11756",
    "CVE-2019-12450",
    "CVE-2019-12749",
    "CVE-2019-14822",
    "CVE-2019-14866",
    "CVE-2019-15903",
    "CVE-2019-16935",
    "CVE-2019-17006",
    "CVE-2019-17023",
    "CVE-2019-17498",
    "CVE-2019-19126",
    "CVE-2019-19956",
    "CVE-2019-20386",
    "CVE-2019-20388",
    "CVE-2019-20485",
    "CVE-2019-20907",
    "CVE-2020-2574",
    "CVE-2020-2752",
    "CVE-2020-2780",
    "CVE-2020-2812",
    "CVE-2020-6829",
    "CVE-2020-7595",
    "CVE-2020-8177",
    "CVE-2020-8492",
    "CVE-2020-8622",
    "CVE-2020-8623",
    "CVE-2020-8624",
    "CVE-2020-10703",
    "CVE-2020-12243",
    "CVE-2020-12400",
    "CVE-2020-12401",
    "CVE-2020-12402",
    "CVE-2020-12403",
    "CVE-2020-12825",
    "CVE-2020-14422",
    "CVE-2020-15999",
    "CVE-2020-25637"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20201105.1021)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20201105.1021. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20201105.1021 advisory.

  - libpng before 1.6.32 does not properly check the length of chunks against the user limit. (CVE-2017-12652)

  - In libexpat in Expat before 2.2.7, XML input including XML names that contain a large number of colons
    could make the XML parser consume a high amount of RAM and CPU resources while processing (enough to be
    usable for denial-of-service attacks). (CVE-2018-20843)

  - When importing a curve25519 private key in PKCS#8format with leading 0x00 bytes, it is possible to trigger
    an out-of-bounds read in the Network Security Services (NSS) library. This could lead to information
    disclosure. This vulnerability affects Firefox ESR < 60.8, Firefox < 68, and Thunderbird < 60.8.
    (CVE-2019-11719)

  - A vulnerability exists where it possible to force Network Security Services (NSS) to sign
    CertificateVerify with PKCS#1 v1.5 signatures when those are the only ones advertised by server in
    CertificateRequest in TLS 1.3. PKCS#1 v1.5 signatures should not be used for TLS 1.3 messages. This
    vulnerability affects Firefox < 68. (CVE-2019-11727)

  - Improper refcounting of soft token session objects could cause a use-after-free and crash (likely limited
    to a denial of service). This vulnerability affects Firefox < 71. (CVE-2019-11756)

  - file_copy_fallback in gio/gfile.c in GNOME GLib 2.15.0 through 2.61.1 does not properly restrict file
    permissions while a copy operation is in progress. Instead, default permissions are used. (CVE-2019-12450)

  - dbus before 1.10.28, 1.12.x before 1.12.16, and 1.13.x before 1.13.12, as used in DBusServer in Canonical
    Upstart in Ubuntu 14.04 (and in some, less common, uses of dbus-daemon), allows cookie spoofing because of
    symlink mishandling in the reference implementation of DBUS_COOKIE_SHA1 in the libdbus library. (This only
    affects the DBUS_COOKIE_SHA1 authentication mechanism.) A malicious client with write access to its own
    home directory could manipulate a ~/.dbus-keyrings symlink to cause a DBusServer with a different uid to
    read and write in unintended locations. In the worst case, this could result in the DBusServer reusing a
    cookie that is known to the malicious client, and treating that cookie as evidence that a subsequent
    client connection came from an attacker-chosen uid, allowing authentication bypass. (CVE-2019-12749)

  - A flaw was discovered in ibus in versions before 1.5.22 that allows any unprivileged user to monitor and
    send method calls to the ibus bus of another user due to a misconfiguration in the DBus server setup. A
    local attacker may use this flaw to intercept all keystrokes of a victim user who is using the graphical
    interface, change the input method engine, or modify other input related configurations of the victim
    user. (CVE-2019-14822)

  - In all versions of cpio before 2.13 does not properly validate input files when generating TAR archives.
    When cpio is used to create TAR archives from paths an attacker can write to, the resulting archive may
    contain files with permissions the attacker did not have or in paths he did not have access to. Extracting
    those archives from a high-privilege user without carefully reviewing them may lead to the compromise of
    the system. (CVE-2019-14866)

  - In libexpat before 2.2.8, crafted XML input could fool the parser into changing from DTD parsing to
    document parsing too early; a consecutive call to XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber)
    then resulted in a heap-based buffer over-read. (CVE-2019-15903)

  - The documentation XML-RPC server in Python through 2.7.16, 3.x through 3.6.9, and 3.7.x through 3.7.4 has
    XSS via the server_title field. This occurs in Lib/DocXMLRPCServer.py in Python 2.x, and in
    Lib/xmlrpc/server.py in Python 3.x. If set_server_title is called with untrusted input, arbitrary
    JavaScript can be delivered to clients that visit the http URL for this server. (CVE-2019-16935)

  - In Network Security Services (NSS) before 3.46, several cryptographic primitives had missing length
    checks. In cases where the application calling the library did not perform a sanity check on the inputs it
    could result in a crash due to a buffer overflow. (CVE-2019-17006)

  - After a HelloRetryRequest has been sent, the client may negotiate a lower protocol that TLS 1.3, resulting
    in an invalid state transition in the TLS State Machine. If the client gets into this state, incoming
    Application Data records will be ignored. This vulnerability affects Firefox < 72. (CVE-2019-17023)

  - In libssh2 v1.9.0 and earlier versions, the SSH_MSG_DISCONNECT logic in packet.c has an integer overflow
    in a bounds check, enabling an attacker to specify an arbitrary (out-of-bounds) offset for a subsequent
    memory read. A crafted SSH server may be able to disclose sensitive information or cause a denial of
    service condition on the client system when a user connects to the server. (CVE-2019-17498)

  - On the x86-64 architecture, the GNU C Library (aka glibc) before 2.31 fails to ignore the
    LD_PREFER_MAP_32BIT_EXEC environment variable during program execution after a security transition,
    allowing local attackers to restrict the possible mapping addresses for loaded libraries and thus bypass
    ASLR for a setuid program. (CVE-2019-19126)

  - xmlParseBalancedChunkMemoryRecover in parser.c in libxml2 before 2.9.10 has a memory leak related to
    newDoc->oldNs. (CVE-2019-19956)

  - An issue was discovered in button_open in login/logind-button.c in systemd before 243. When executing the
    udevadm trigger command, a memory leak may occur. (CVE-2019-20386)

  - xmlSchemaPreRun in xmlschemas.c in libxml2 2.9.10 allows an xmlSchemaValidateStream memory leak.
    (CVE-2019-20388)

  - qemu/qemu_driver.c in libvirt before 6.0.0 mishandles the holding of a monitor job during a query to a
    guest agent, which allows attackers to cause a denial of service (API blockage). (CVE-2019-20485)

  - In Lib/tarfile.py in Python through 3.8.3, an attacker is able to craft a TAR archive leading to an
    infinite loop when opened by tarfile.open, because _proc_pax lacks header validation. (CVE-2019-20907)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.6.45 and prior, 5.7.27 and prior and 8.0.17 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2974)

  - An exploitable code execution vulnerability exists in the quota file functionality of E2fsprogs 1.45.3. A
    specially crafted ext4 partition can cause an out-of-bounds write on the heap, resulting in code
    execution. An attacker can corrupt a partition to trigger this vulnerability. (CVE-2019-5094)

  - A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4.
    A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code
    execution. An attacker can corrupt a partition to trigger this vulnerability. (CVE-2019-5188)

  - Heap buffer overflow in the TFTP protocol handler in cURL 7.19.4 to 7.65.3. (CVE-2019-5482)

  - A NULL pointer dereference was found in the libvirt API responsible introduced in upstream version 3.10.0,
    and fixed in libvirt 6.0.0, for fetching a storage pool based on its target path. In more detail, this
    flaw affects storage pools created without a target path such as network-based pools like gluster and RBD.
    Unprivileged users with a read-only connection could abuse this flaw to crash the libvirt daemon,
    resulting in a potential denial of service. (CVE-2020-10703)

  - In filter.c in slapd in OpenLDAP before 2.4.50, LDAP search filters with nested boolean expressions can
    result in denial of service (daemon crash). (CVE-2020-12243)

  - When converting coordinates from projective to affine, the modular inversion was not performed in constant
    time, resulting in a possible timing-based side channel attack. This vulnerability affects Firefox < 80
    and Firefox for Android < 80. (CVE-2020-12400)

  - During ECDSA signature generation, padding applied in the nonce designed to ensure constant-time scalar
    multiplication was removed, resulting in variable-time execution dependent on secret data. This
    vulnerability affects Firefox < 80 and Firefox for Android < 80. (CVE-2020-12401)

  - During RSA key generation, bignum implementations used a variation of the Binary Extended Euclidean
    Algorithm which entailed significantly input-dependent flow. This allowed an attacker able to perform
    electromagnetic-based side channel attacks to record traces leading to the recovery of the secret primes.
    *Note:* An unmodified Firefox browser does not generate RSA keys in normal operation and is not affected,
    but products built on top of it might. This vulnerability affects Firefox < 78. (CVE-2020-12402)

  - A flaw was found in the way CHACHA20-POLY1305 was implemented in NSS in versions before 3.55. When using
    multi-part Chacha20, it could cause out-of-bounds reads. This issue was fixed by explicitly disabling
    multi-part ChaCha20 (which was not functioning correctly) and strictly enforcing tag length. The highest
    threat from this vulnerability is to confidentiality and system availability. (CVE-2020-12403)

  - libcroco through 0.6.13 has excessive recursion in cr_parser_parse_any_core in cr-parser.c, leading to
    stack consumption. (CVE-2020-12825)

  - Lib/ipaddress.py in Python through 3.8.3 improperly computes hash values in the IPv4Interface and
    IPv6Interface classes, which might allow a remote attacker to cause a denial of service if an application
    is affected by the performance of a dictionary containing IPv4Interface or IPv6Interface objects, and this
    attacker can cause many dictionary entries to be created. This is fixed in: v3.5.10, v3.5.10rc1; v3.6.12;
    v3.7.9; v3.8.4, v3.8.4rc1, v3.8.5, v3.8.6, v3.8.6rc1; v3.9.0, v3.9.0b4, v3.9.0b5, v3.9.0rc1, v3.9.0rc2.
    (CVE-2020-14422)

  - Heap buffer overflow in Freetype in Google Chrome prior to 86.0.4240.111 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-15999)

  - A double free memory issue was found to occur in the libvirt API, in versions before 6.8.0, responsible
    for requesting information about network interfaces of a running QEMU domain. This flaw affects the polkit
    access control driver. Specifically, clients connecting to the read-write socket with limited ACL
    permissions could use this flaw to crash the libvirt daemon, resulting in a denial of service, or
    potentially escalate their privileges on the system. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25637)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.46 and prior, 5.7.28 and prior and 8.0.18 and prior. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. (CVE-2020-2574)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.47 and prior, 5.7.27 and prior and 8.0.17 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. (CVE-2020-2752)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2020-2780)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2020-2812)

  - When performing EC scalar point multiplication, the wNAF point multiplication algorithm was used; which
    leaked partial information about the nonce used during signature generation. Given an electro-magnetic
    trace of a few signature generations, the private key could have been computed. This vulnerability affects
    Firefox < 80 and Firefox for Android < 80. (CVE-2020-6829)

  - xmlStringLenDecodeEntities in parser.c in libxml2 2.9.10 has an infinite loop in a certain end-of-file
    situation. (CVE-2020-7595)

  - curl 7.20.0 through 7.70.0 is vulnerable to improper restriction of names for files and other resources
    that can lead too overwriting a local file when the -J flag is used. (CVE-2020-8177)

  - Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6 through 3.6.10, 3.7 through 3.7.6, and 3.8 through 3.8.1
    allows an HTTP server to conduct Regular Expression Denial of Service (ReDoS) attacks against a client
    because of urllib.request.AbstractBasicAuthHandler catastrophic backtracking. (CVE-2020-8492)

  - In BIND 9.0.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.9.3-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker on the network path for a TSIG-signed request, or operating
    the server receiving the TSIG-signed request, could send a truncated response to that request, triggering
    an assertion failure, causing the server to exit. Alternately, an off-path attacker would have to
    correctly guess when a TSIG-signed request was sent, along with other characteristics of the packet and
    message, and spoof a truncated response to trigger an assertion failure, causing the server to exit.
    (CVE-2020-8622)

  - In BIND 9.10.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.10.5-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker that can reach a vulnerable system with a specially crafted
    query packet can trigger a crash. To be vulnerable, the system must: * be running BIND that was built with
    --enable-native-pkcs11 * be signing one or more zones with an RSA key * be able to receive queries from
    a possible attacker (CVE-2020-8623)

  - In BIND 9.9.12 -> 9.9.13, 9.10.7 -> 9.10.8, 9.11.3 -> 9.11.21, 9.12.1 -> 9.16.5, 9.17.0 -> 9.17.3, also
    affects 9.9.12-S1 -> 9.9.13-S1, 9.11.3-S1 -> 9.11.21-S1 of the BIND 9 Supported Preview Edition, An
    attacker who has been granted privileges to change a specific subset of the zone's content could abuse
    these unintended additional privileges to update other contents of the zone. (CVE-2020-8624)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20201105.1021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?085dcec0");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5482");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/Node/Version", "Host/Nutanix/Data/Node/Type");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info(node:TRUE);

var constraints = [
  { 'fixed_version' : '20201105.1021', 'product' : 'AHV', 'fixed_display' : 'Upgrade the AHV install to 20201105.1021 or higher.' }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
