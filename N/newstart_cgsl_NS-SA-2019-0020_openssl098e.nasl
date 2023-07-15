#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0020. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127177);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2006-2937",
    "CVE-2006-2940",
    "CVE-2006-3738",
    "CVE-2006-4339",
    "CVE-2006-4343",
    "CVE-2007-3108",
    "CVE-2007-4995",
    "CVE-2007-5135",
    "CVE-2008-5077",
    "CVE-2009-0590",
    "CVE-2009-1377",
    "CVE-2009-1378",
    "CVE-2009-1379",
    "CVE-2009-1386",
    "CVE-2009-1387",
    "CVE-2009-2409",
    "CVE-2009-3245",
    "CVE-2009-3555",
    "CVE-2009-4355",
    "CVE-2010-0433",
    "CVE-2012-2110",
    "CVE-2012-4929",
    "CVE-2013-0166",
    "CVE-2013-0169"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : openssl098e Multiple Vulnerabilities (NS-SA-2019-0020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has openssl098e packages installed that are
affected by multiple vulnerabilities:

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

  - OpenSSL 0.9.8i and earlier does not properly check the
    return value from the EVP_VerifyFinal function, which
    allows remote attackers to bypass validation of the
    certificate chain via a malformed SSL/TLS signature for
    DSA and ECDSA keys. (CVE-2008-5077)

  - The ASN1_STRING_print_ex function in OpenSSL before
    0.9.8k allows remote attackers to cause a denial of
    service (invalid memory access and application crash)
    via vectors that trigger printing of a (1) BMPString or
    (2) UniversalString with an invalid encoded length.
    (CVE-2009-0590)

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

  - ssl/s3_pkt.c in OpenSSL before 0.9.8i allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and daemon crash) via a DTLS
    ChangeCipherSpec packet that occurs before ClientHello.
    (CVE-2009-1386)

  - The dtls1_retrieve_buffered_fragment function in
    ssl/d1_both.c in OpenSSL before 1.0.0 Beta 2 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and daemon crash) via an out-of-
    sequence DTLS handshake message, related to a fragment
    bug. (CVE-2009-1387)

  - The Network Security Services (NSS) library before
    3.12.3, as used in Firefox; GnuTLS before 2.6.4 and
    2.7.4; OpenSSL 0.9.8 through 0.9.8k; and other products
    support MD2 with X.509 certificates, which might allow
    remote attackers to spoof certificates by using MD2
    design flaws to generate a hash collision in less than
    brute-force time. NOTE: the scope of this issue is
    currently limited because the amount of computation
    required is still large. (CVE-2009-2409)

  - OpenSSL before 0.9.8m does not check for a NULL return
    value from bn_wexpand function calls in (1)
    crypto/bn/bn_div.c, (2) crypto/bn/bn_gf2m.c, (3)
    crypto/ec/ec2_smpl.c, and (4) engines/e_ubsec.c, which
    has unspecified impact and context-dependent attack
    vectors. (CVE-2009-3245)

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

  - The kssl_keytab_is_available function in ssl/kssl.c in
    OpenSSL before 0.9.8n, when Kerberos is enabled but
    Kerberos configuration files cannot be opened, does not
    check a certain return value, which allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and daemon crash) via SSL cipher
    negotiation, as demonstrated by a chroot installation of
    Dovecot or stunnel without Kerberos configuration files
    inside the chroot. (CVE-2010-0433)

  - The asn1_d2i_read_bio function in crypto/asn1/a_d2i_fp.c
    in OpenSSL before 0.9.8v, 1.0.0 before 1.0.0i, and 1.0.1
    before 1.0.1a does not properly interpret integer data,
    which allows remote attackers to conduct buffer overflow
    attacks, and cause a denial of service (memory
    corruption) or possibly have unspecified other impact,
    via crafted DER data, as demonstrated by an X.509
    certificate or an RSA public key. (CVE-2012-2110)

  - The TLS protocol 1.2 and earlier, as used in Mozilla
    Firefox, Google Chrome, Qt, and other products, can
    encrypt compressed data without properly obfuscating the
    length of the unencrypted data, which allows man-in-the-
    middle attackers to obtain plaintext HTTP headers by
    observing length differences during a series of guesses
    in which a string in an HTTP request potentially matches
    an unknown string in an HTTP header, aka a CRIME
    attack. (CVE-2012-4929)

  - OpenSSL before 0.9.8y, 1.0.0 before 1.0.0k, and 1.0.1
    before 1.0.1d does not properly perform signature
    verification for OCSP responses, which allows remote
    OCSP servers to cause a denial of service (NULL pointer
    dereference and application crash) via an invalid key.
    (CVE-2013-0166)

  - The TLS protocol 1.1 and 1.2 and the DTLS protocol 1.0
    and 1.2, as used in OpenSSL, OpenJDK, PolarSSL, and
    other products, do not properly consider timing side-
    channel attacks on a MAC check requirement during the
    processing of malformed CBC padding, which allows remote
    attackers to conduct distinguishing attacks and
    plaintext-recovery attacks via statistical analysis of
    timing data for crafted packets, aka the Lucky
    Thirteen issue. (CVE-2013-0169)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0020");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL openssl098e packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3245");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119, 189, 310, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
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
    "openssl098e-0.9.8e-29.el7.centos.3",
    "openssl098e-debuginfo-0.9.8e-29.el7.centos.3"
  ],
  "CGSL MAIN 5.04": [
    "openssl098e-0.9.8e-29.el7.centos.3",
    "openssl098e-debuginfo-0.9.8e-29.el7.centos.3"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl098e");
}
