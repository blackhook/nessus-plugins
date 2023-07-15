#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0033. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127201);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2006-2937",
    "CVE-2006-2940",
    "CVE-2006-3738",
    "CVE-2006-4339",
    "CVE-2006-4343",
    "CVE-2007-3108",
    "CVE-2007-4995",
    "CVE-2007-5135",
    "CVE-2008-0891",
    "CVE-2008-1672",
    "CVE-2009-1377",
    "CVE-2009-1378",
    "CVE-2009-1379",
    "CVE-2009-3555",
    "CVE-2009-4355",
    "CVE-2010-0742",
    "CVE-2010-1633",
    "CVE-2010-3864",
    "CVE-2010-4180",
    "CVE-2011-0014",
    "CVE-2011-3207",
    "CVE-2012-0050",
    "CVE-2012-2110",
    "CVE-2013-4353",
    "CVE-2013-6449",
    "CVE-2013-6450",
    "CVE-2014-0160",
    "CVE-2014-3566",
    "CVE-2016-2183",
    "CVE-2017-3736",
    "CVE-2017-3737",
    "CVE-2017-3738"
  );
  script_bugtraq_id(92630);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : openssl Multiple Vulnerabilities (NS-SA-2019-0033)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has openssl packages installed that are affected
by multiple vulnerabilities:

  - OpenSSL 1.0.2 (starting from version 1.0.2b) introduced
    an error state mechanism. The intent was that if a
    fatal error occurred during a handshake then OpenSSL
    would move into the error state and would immediately
    fail if you attempted to continue the handshake. This
    works as designed for the explicit handshake functions
    (SSL_do_handshake(), SSL_accept() and SSL_connect()),
    however due to a bug it does not work correctly if
    SSL_read() or SSL_write() is called directly. In that
    scenario, if the handshake fails then a fatal error will
    be returned in the initial function call. If
    SSL_read()/SSL_write() is subsequently called by the
    application for the same SSL object then it will succeed
    and the data is passed without being decrypted/encrypted
    directly from the SSL/TLS record layer. In order to
    exploit this issue an application bug would have to be
    present that resulted in a call to
    SSL_read()/SSL_write() being issued after having already
    received a fatal error. OpenSSL version 1.0.2b-1.0.2m
    are affected. Fixed in OpenSSL 1.0.2n. OpenSSL 1.1.0 is
    not affected. (CVE-2017-3737)

  - There is an overflow bug in the AVX2 Montgomery
    multiplication procedure used in exponentiation with
    1024-bit moduli. No EC algorithms are affected. Analysis
    suggests that attacks against RSA and DSA as a result of
    this defect would be very difficult to perform and are
    not believed likely. Attacks against DH1024 are
    considered just feasible, because most of the work
    necessary to deduce information about a private key may
    be performed offline. The amount of resources required
    for such an attack would be significant. However, for an
    attack on TLS to be meaningful, the server would have to
    share the DH1024 private key among multiple clients,
    which is no longer an option since CVE-2016-0701. This
    only affects processors that support the AVX2 but not
    ADX extensions like Intel Haswell (4th generation).
    Note: The impact from this issue is similar to
    CVE-2017-3736, CVE-2017-3732 and CVE-2015-3193. OpenSSL
    version 1.0.2-1.0.2m and 1.1.0-1.1.0g are affected.
    Fixed in OpenSSL 1.0.2n. Due to the low severity of this
    issue we are not issuing a new release of OpenSSL 1.1.0
    at this time. The fix will be included in OpenSSL 1.1.0h
    when it becomes available. The fix is also available in
    commit e502cc86d in the OpenSSL git repository.
    (CVE-2017-3738)

  - There is a carry propagating bug in the x86_64
    Montgomery squaring procedure in OpenSSL before 1.0.2m
    and 1.1.0 before 1.1.0g. No EC algorithms are affected.
    Analysis suggests that attacks against RSA and DSA as a
    result of this defect would be very difficult to perform
    and are not believed likely. Attacks against DH are
    considered just feasible (although very difficult)
    because most of the work necessary to deduce information
    about a private key may be performed offline. The amount
    of resources required for such an attack would be very
    significant and likely only accessible to a limited
    number of attackers. An attacker would additionally need
    online access to an unpatched system using the target
    private key in a scenario with persistent DH parameters
    and a private key that is shared between multiple
    clients. This only affects processors that support the
    BMI1, BMI2 and ADX extensions like Intel Broadwell (5th
    generation) and later or AMD Ryzen. (CVE-2017-3736)

  - OpenSSL 0.9.7 before 0.9.7l and 0.9.8 before 0.9.8d
    allows remote attackers to cause a denial of service
    (infinite loop and memory consumption) via malformed
    ASN.1 structures that trigger an improperly handled
    error condition. (CVE-2006-2937)

  - OpenSSL 0.9.7 before 0.9.7l, 0.9.8 before 0.9.8d, and
    earlier versions allows attackers to cause a denial of
    service (CPU consumption) via parasitic public keys with
    large (1) public exponent or (2) public modulus
    values in X.509 certificates that require extra time to
    process when using RSA signature verification.
    (CVE-2006-2940)

  - Buffer overflow in the SSL_get_shared_ciphers function
    in OpenSSL 0.9.7 before 0.9.7l, 0.9.8 before 0.9.8d, and
    earlier versions has unspecified impact and remote
    attack vectors involving a long list of ciphers.
    (CVE-2006-3738)

  - OpenSSL before 0.9.7, 0.9.7 before 0.9.7k, and 0.9.8
    before 0.9.8c, when using an RSA key with exponent 3,
    removes PKCS-1 padding before generating a hash, which
    allows remote attackers to forge a PKCS #1 v1.5
    signature that is signed by that RSA key and prevents
    OpenSSL from correctly verifying X.509 and other
    certificates that use PKCS #1. (CVE-2006-4339)

  - The get_server_hello function in the SSLv2 client code
    in OpenSSL 0.9.7 before 0.9.7l, 0.9.8 before 0.9.8d, and
    earlier versions allows remote servers to cause a denial
    of service (client crash) via unknown vectors that
    trigger a null pointer dereference. (CVE-2006-4343)

  - The BN_from_montgomery function in crypto/bn/bn_mont.c
    in OpenSSL 0.9.8e and earlier does not properly perform
    Montgomery multiplication, which might allow local users
    to conduct a side-channel attack and retrieve RSA
    private keys. (CVE-2007-3108)

  - Off-by-one error in the DTLS implementation in OpenSSL
    0.9.8 before 0.9.8f allows remote attackers to execute
    arbitrary code via unspecified vectors. (CVE-2007-4995)

  - Off-by-one error in the SSL_get_shared_ciphers function
    in OpenSSL 0.9.7 up to 0.9.7l, and 0.9.8 up to 0.9.8f,
    might allow remote attackers to execute arbitrary code
    via a crafted packet that triggers a one-byte buffer
    underflow. NOTE: this issue was introduced as a result
    of a fix for CVE-2006-3738. As of 20071012, it is
    unknown whether code execution is possible.
    (CVE-2007-5135)

  - Double free vulnerability in OpenSSL 0.9.8f and 0.9.8g,
    when the TLS server name extensions are enabled, allows
    remote attackers to cause a denial of service (crash)
    via a malformed Client Hello packet. NOTE: some of these
    details are obtained from third party information.
    (CVE-2008-0891)

  - OpenSSL 0.9.8f and 0.9.8g allows remote attackers to
    cause a denial of service (crash) via a TLS handshake
    that omits the Server Key Exchange message and uses
    particular cipher suites, which triggers a NULL
    pointer dereference. (CVE-2008-1672)

  - The dtls1_buffer_record function in ssl/d1_pkt.c in
    OpenSSL 0.9.8k and earlier 0.9.8 versions allows remote
    attackers to cause a denial of service (memory
    consumption) via a large series of future epoch DTLS
    records that are buffered in a queue, aka DTLS record
    buffer limitation bug. (CVE-2009-1377)

  - Multiple memory leaks in the
    dtls1_process_out_of_seq_message function in
    ssl/d1_both.c in OpenSSL 0.9.8k and earlier 0.9.8
    versions allow remote attackers to cause a denial of
    service (memory consumption) via DTLS records that (1)
    are duplicates or (2) have sequence numbers much greater
    than current sequence numbers, aka DTLS fragment
    handling memory leak. (CVE-2009-1378)

  - Use-after-free vulnerability in the
    dtls1_retrieve_buffered_fragment function in
    ssl/d1_both.c in OpenSSL 1.0.0 Beta 2 allows remote
    attackers to cause a denial of service (openssl s_client
    crash) and possibly have unspecified other impact via a
    DTLS packet, as demonstrated by a packet from a server
    that uses a crafted server certificate. (CVE-2009-1379)

  - The TLS protocol, and the SSL protocol 3.0 and possibly
    earlier, as used in Microsoft Internet Information
    Services (IIS) 7.0, mod_ssl in the Apache HTTP Server
    2.2.14 and earlier, OpenSSL before 0.9.8l, GnuTLS 2.8.5
    and earlier, Mozilla Network Security Services (NSS)
    3.12.4 and earlier, multiple Cisco products, and other
    products, does not properly associate renegotiation
    handshakes with an existing connection, which allows
    man-in-the-middle attackers to insert data into HTTPS
    sessions, and possibly other types of sessions protected
    by TLS or SSL, by sending an unauthenticated request
    that is processed retroactively by a server in a post-
    renegotiation context, related to a plaintext
    injection attack, aka the Project Mogul issue.
    (CVE-2009-3555)

  - Memory leak in the zlib_stateful_finish function in
    crypto/comp/c_zlib.c in OpenSSL 0.9.8l and earlier and
    1.0.0 Beta through Beta 4 allows remote attackers to
    cause a denial of service (memory consumption) via
    vectors that trigger incorrect calls to the
    CRYPTO_cleanup_all_ex_data function, as demonstrated by
    use of SSLv3 and PHP with the Apache HTTP Server, a
    related issue to CVE-2008-1678. (CVE-2009-4355)

  - The Cryptographic Message Syntax (CMS) implementation in
    crypto/cms/cms_asn1.c in OpenSSL before 0.9.8o and 1.x
    before 1.0.0a does not properly handle structures that
    contain OriginatorInfo, which allows context-dependent
    attackers to modify invalid memory locations or conduct
    double-free attacks, and possibly execute arbitrary
    code, via unspecified vectors. (CVE-2010-0742)

  - RSA verification recovery in the EVP_PKEY_verify_recover
    function in OpenSSL 1.x before 1.0.0a, as used by
    pkeyutl and possibly other applications, returns
    uninitialized memory upon failure, which might allow
    context-dependent attackers to bypass intended key
    requirements or obtain sensitive information via
    unspecified vectors. NOTE: some of these details are
    obtained from third party information. (CVE-2010-1633)

  - Multiple race conditions in ssl/t1_lib.c in OpenSSL
    0.9.8f through 0.9.8o, 1.0.0, and 1.0.0a, when multi-
    threading and internal caching are enabled on a TLS
    server, might allow remote attackers to execute
    arbitrary code via client data that triggers a heap-
    based buffer overflow, related to (1) the TLS server
    name extension and (2) elliptic curve cryptography.
    (CVE-2010-3864)

  - OpenSSL before 0.9.8q, and 1.0.x before 1.0.0c, when
    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG is enabled, does
    not properly prevent modification of the ciphersuite in
    the session cache, which allows remote attackers to
    force the downgrade to an unintended cipher via vectors
    involving sniffing network traffic to discover a session
    identifier. (CVE-2010-4180)

  - ssl/t1_lib.c in OpenSSL 0.9.8h through 0.9.8q and 1.0.0
    through 1.0.0c allows remote attackers to cause a denial
    of service (crash), and possibly obtain sensitive
    information in applications that use OpenSSL, via a
    malformed ClientHello handshake message that triggers an
    out-of-bounds memory access, aka OCSP stapling
    vulnerability. (CVE-2011-0014)

  - crypto/x509/x509_vfy.c in OpenSSL 1.0.x before 1.0.0e
    does not initialize certain structure members, which
    makes it easier for remote attackers to bypass CRL
    validation by using a nextUpdate value corresponding to
    a time in the past. (CVE-2011-3207)

  - OpenSSL 0.9.8s and 1.0.0f does not properly support DTLS
    applications, which allows remote attackers to cause a
    denial of service (crash) via unspecified vectors
    related to an out-of-bounds read. NOTE: this
    vulnerability exists because of an incorrect fix for
    CVE-2011-4108. (CVE-2012-0050)

  - The asn1_d2i_read_bio function in crypto/asn1/a_d2i_fp.c
    in OpenSSL before 0.9.8v, 1.0.0 before 1.0.0i, and 1.0.1
    before 1.0.1a does not properly interpret integer data,
    which allows remote attackers to conduct buffer overflow
    attacks, and cause a denial of service (memory
    corruption) or possibly have unspecified other impact,
    via crafted DER data, as demonstrated by an X.509
    certificate or an RSA public key. (CVE-2012-2110)

  - The ssl3_take_mac function in ssl/s3_both.c in OpenSSL
    1.0.1 before 1.0.1f allows remote TLS servers to cause a
    denial of service (NULL pointer dereference and
    application crash) via a crafted Next Protocol
    Negotiation record in a TLS handshake. (CVE-2013-4353)

  - The ssl_get_algorithm2 function in ssl/s3_lib.c in
    OpenSSL before 1.0.2 obtains a certain version number
    from an incorrect data structure, which allows remote
    attackers to cause a denial of service (daemon crash)
    via crafted traffic from a TLS 1.2 client.
    (CVE-2013-6449)

  - The DTLS retransmission implementation in OpenSSL 1.0.0
    before 1.0.0l and 1.0.1 before 1.0.1f does not properly
    maintain data structures for digest and encryption
    contexts, which might allow man-in-the-middle attackers
    to trigger the use of a different context and cause a
    denial of service (application crash) by interfering
    with packet delivery, related to ssl/d1_both.c and
    ssl/t1_enc.c. (CVE-2013-6450)

  - An information disclosure flaw was found in the way
    OpenSSL handled TLS and DTLS Heartbeat Extension
    packets. A malicious TLS or DTLS client or server could
    send a specially crafted TLS or DTLS Heartbeat packet to
    disclose a limited portion of memory per request from a
    connected client or server. Note that the disclosed
    portions of memory could potentially include sensitive
    information such as private keys. (CVE-2014-0160)

  - A flaw was found in the way SSL 3.0 handled padding
    bytes when decrypting messages encrypted using block
    ciphers in cipher block chaining (CBC) mode. This flaw
    allows a man-in-the-middle (MITM) attacker to decrypt a
    selected byte of a cipher text in as few as 256 tries if
    they are able to force a victim application to
    repeatedly send the same data over newly created SSL 3.0
    connections. (CVE-2014-3566)

  - A flaw was found in the way the DES/3DES cipher was used
    as part of the TLS/SSL protocol. A man-in-the-middle
    attacker could use this flaw to recover some plaintext
    data by capturing large amounts of encrypted traffic
    between TLS/SSL server and client if the communication
    used a DES/3DES based ciphersuite. (CVE-2016-2183)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0033");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL openssl packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-3738");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-2183");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 287, 310, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "openssl-1.0.2k-12.el7.cgslv5lite.0.1.g0e5ddfd",
    "openssl-crypto-1.0.2k-12.el7.cgslv5lite.0.1.g0e5ddfd",
    "openssl-debuginfo-1.0.2k-12.el7.cgslv5lite.0.1.g0e5ddfd",
    "openssl-devel-1.0.2k-12.el7.cgslv5lite.0.1.g0e5ddfd",
    "openssl-libs-1.0.2k-12.el7.cgslv5lite.0.1.g0e5ddfd",
    "openssl-perl-1.0.2k-12.el7.cgslv5lite.0.1.g0e5ddfd",
    "openssl-static-1.0.2k-12.el7.cgslv5lite.0.1.g0e5ddfd"
  ],
  "CGSL MAIN 5.04": [
    "openssl-1.0.2k-12.el7.cgslv5",
    "openssl-debuginfo-1.0.2k-12.el7.cgslv5",
    "openssl-devel-1.0.2k-12.el7.cgslv5",
    "openssl-libs-1.0.2k-12.el7.cgslv5",
    "openssl-perl-1.0.2k-12.el7.cgslv5",
    "openssl-static-1.0.2k-12.el7.cgslv5"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
