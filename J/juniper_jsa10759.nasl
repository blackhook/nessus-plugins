#TRUSTED 4a1406c695c878696a86e068ac0059fdf28b0a5ca6e931f33b9fcdeb011c093eebe0c4d805fc6a1e8b9881b189b8d299e246224403c54cde12b10352c1a61ef8614967a5ccdd170d07d68e45b307c9992fc399974819e0b39b96130a2a973f1acfb54b8ded6d905456661a1e4bfffcd9f387a52a9870094e9ae010bf7c7da13fb431ffddc77c0723cdd4c9857509368070950998800c065f54ac172ed6ec1985d601e718e844c760a9b50cbf20544e9bdc582f2a84d88a37522be8f2316fcf866b24ec315ebfb3a82f079f5dd388ecb0cef3b32b94c3f320cced1b22a0fa765bdd240fd4bd2b6c22511bdeab8a049d01a5ed789a2a43aad42a93c8ede658ed95c3c3c44a95e822ccb2f7999bb1b586752908ae3942c82cd37ea3e24bfc980f0904b62bbfe030fdb72b5aaead4f9246f22fb69e27cc5a55bd1a49a7de64e868c6bfc9bcc7752c7c731436f484f137d0b764361eb4701c2e74c4c18b8709b0625b61d1b034e9bf50cadfe90b42e5528d6b752ca246559df558227f289e4846ce10ea3c0271511c6850099cf96432144bf78bc4b6121ad4fcdb120b0f2da49cd5260667f643c8b7ca9967c47a34a33cb8617b831bd575438e585d051f411c2d931a0b46a63a1a3549cc5b0be76767467800806eafc691f603c87fadeacbc7c4a2d51f5861e245c7804a7534ea882c6d144ba1803d2e01fba97bd12521bc285c9a10
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96316);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id(
    "CVE-2015-1794",
    "CVE-2015-3193",
    "CVE-2015-3194",
    "CVE-2015-3195",
    "CVE-2015-3196",
    "CVE-2015-3197",
    "CVE-2016-0702",
    "CVE-2016-0703",
    "CVE-2016-0704",
    "CVE-2016-0705",
    "CVE-2016-0797",
    "CVE-2016-0798",
    "CVE-2016-0799",
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2108",
    "CVE-2016-2109",
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2180",
    "CVE-2016-2182",
    "CVE-2016-2183",
    "CVE-2016-6302",
    "CVE-2016-6303",
    "CVE-2016-6304",
    "CVE-2016-6305",
    "CVE-2016-6306",
    "CVE-2016-6307"
  );
  script_bugtraq_id(
    78622,
    78623,
    78626,
    82237,
    83705,
    83743,
    83754,
    83755,
    83763,
    83764,
    87940,
    89744,
    89752,
    89757,
    91081,
    91319,
    92117,
    92557,
    92628,
    92630,
    92984,
    93149,
    93150,
    93152,
    93153
  );
  script_xref(name:"JSA", value:"JSA10759");

  script_name(english:"Juniper Junos Multiple OpenSSL Vulnerabilities (JSA10759) (SWEET32)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by the following vulnerabilities related to
OpenSSL :

  - A flaw exists in the ssl3_get_key_exchange() function
    in file s3_clnt.c when handling a ServerKeyExchange
    message for an anonymous DH ciphersuite with the value
    of 'p' set to 0. A attacker can exploit this, by causing
    a segmentation fault, to crash an application linked
    against the library, resulting in a denial of service.
    (CVE-2015-1794)

  - A carry propagating flaw exists in the x86_64 Montgomery
    squaring implementation that may cause the BN_mod_exp()
    function to produce incorrect results. An attacker can
    exploit this to obtain sensitive information regarding
    private keys. (CVE-2015-3193)

  - A NULL pointer dereference flaw exists in file
    rsa_ameth.c due to improper handling of ASN.1 signatures
    that are missing the PSS parameter. A remote attacker
    can exploit this to cause the signature verification
    routine to crash, resulting in a denial of service
    condition. (CVE-2015-3194)

  - A flaw exists in the ASN1_TFLG_COMBINE implementation in
    file tasn_dec.c related to handling malformed
    X509_ATTRIBUTE structures. A remote attacker can exploit
    this to cause a memory leak by triggering a decoding
    failure in a PKCS#7 or CMS application, resulting in a
    denial of service. (CVE-2015-3195)

  - A race condition exists in s3_clnt.c that is triggered
    when PSK identity hints are incorrectly updated in the
    parent SSL_CTX structure when they are received by a
    multi-threaded client. A remote attacker can exploit
    this, via a crafted ServerKeyExchange message, to cause
    a double-free memory error, resulting in a denial of
    service. (CVE-2015-3196)

  - A cipher algorithm downgrade vulnerability exists due to
    a flaw that is triggered when handling cipher
    negotiation. A remote attacker can exploit this to
    negotiate SSLv2 ciphers and complete SSLv2 handshakes
    even if all SSLv2 ciphers have been disabled on the
    server. Note that this vulnerability only exists if the
    SSL_OP_NO_SSLv2 option has not been disabled.
    (CVE-2015-3197)

  - A key disclosure vulnerability exists due to improper
    handling of cache-bank conflicts on the Intel
    Sandy-bridge microarchitecture. An attacker can exploit
    this to gain access to RSA key information.
    (CVE-2016-0702)

  - A flaw exists in the SSLv2 implementation,
    specifically in the get_client_master_key() function
    within file s2_srvr.c, due to accepting a nonzero
    CLIENT-MASTER-KEY CLEAR-KEY-LENGTH value for an
    arbitrary cipher. A man-in-the-middle attacker can
    exploit this to determine the MASTER-KEY value and
    decrypt TLS ciphertext by leveraging a Bleichenbacher
    RSA padding oracle. (CVE-2016-0703)

  - A flaw exists in the SSLv2 oracle protection mechanism,
    specifically in the get_client_master_key() function
    within file s2_srvr.c, due to incorrectly overwriting
    MASTER-KEY bytes during use of export cipher suites.
    A remote attackers can exploit this to more easily
    decrypt TLS ciphertext by leveraging a Bleichenbacher
    RSA padding oracle. (CVE-2016-0704)

  - A double-free error exists due to improper validation of
    user-supplied input when parsing malformed DSA private
    keys. A remote attacker can exploit this to corrupt
    memory, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2016-0705)

  - A NULL pointer dereference flaw exists in the
    BN_hex2bn() and BN_dec2bn() functions. A remote attacker
    can exploit this to trigger a heap corruption, resulting
    in the execution of arbitrary code. (CVE-2016-0797)

  - A denial of service vulnerability exists due to improper
    handling of invalid usernames. A remote attacker can
    exploit this, via a specially crafted username, to leak
    300 bytes of memory per connection, exhausting available
    memory resources. (CVE-2016-0798)

  - Multiple memory corruption issues exist that allow a
    remote attacker to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-0799)

  - A heap buffer overflow condition exists in the
    EVP_EncodeUpdate() function within file
    crypto/evp/encode.c that is triggered when handling
    a large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - A heap buffer overflow condition exists in the
    EVP_EncryptUpdate() function within file
    crypto/evp/evp_enc.c that is triggered when handling a
    large amount of input data after a previous call occurs
    to the same function with a partial block. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-2106)

  - A remote code execution vulnerability exists in the
    ASN.1 encoder due to an underflow condition that occurs
    when attempting to encode the value zero represented as
    a negative integer. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in the
    execution of arbitrary code. (CVE-2016-2108)

  - Multiple unspecified flaws exist in the d2i BIO
    functions when reading ASN.1 data from a BIO due to
    invalid encoding causing a large allocation of memory.
    An unauthenticated, remote attacker can exploit these to
    cause a denial of service condition through resource
    exhaustion. (CVE-2016-2109)

  - Multiple integer overflow conditions exist in s3_srvr.c,
    ssl_sess.c, and t1_lib.c due to improper use of pointer
    arithmetic for heap-buffer boundary checks. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service. (CVE-2016-2177)

  - An information disclosure vulnerability exists in the
    dsa_sign_setup() function in dsa_ossl.c due to a failure
    to properly ensure the use of constant-time operations.
    An unauthenticated, remote attacker can exploit this,
    via a timing side-channel attack, to disclose DSA key
    information. (CVE-2016-2178)

  - An out-of-bounds read error exists in the X.509 Public
    Key Infrastructure Time-Stamp Protocol (TSP)
    implementation. An unauthenticated, remote attacker can
    exploit this, via a crafted time-stamp file that is
    mishandled by the 'openssl ts' command, to cause
    denial of service or to disclose sensitive information.
    (CVE-2016-2180)

  - An overflow condition exists in the BN_bn2dec() function
    in bn_print.c due to improper validation of
    user-supplied input when handling BIGNUM values. An
    unauthenticated, remote attacker can exploit this to
    crash the process. (CVE-2016-2182)

  - A vulnerability exists, known as SWEET32, in the 3DES
    and Blowfish algorithms due to the use of weak 64-bit
    block ciphers by default. A man-in-the-middle attacker
    who has sufficient resources can exploit this
    vulnerability, via a 'birthday' attack, to detect a
    collision that leaks the XOR between the fixed secret
    and a known plaintext, allowing the disclosure of the
    secret text, such as secure HTTPS cookies, and possibly
    resulting in the hijacking of an authenticated session.
    (CVE-2016-2183)

  - A flaw exists in the tls_decrypt_ticket() function in
    t1_lib.c due to improper handling of ticket HMAC
    digests. An unauthenticated, remote attacker can exploit
    this, via a ticket that is too short, to crash the
    process, resulting in a denial of service.
    (CVE-2016-6302)

  - An integer overflow condition exists in the
    MDC2_Update() function in mdc2dgst.c due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in a denial of service
    condition or possibly the execution of arbitrary code.
    (CVE-2016-6303)

  - A flaw exists in the ssl_parse_clienthello_tlsext()
    function in t1_lib.c due to improper handling of overly
    large OCSP Status Request extensions from clients. An
    unauthenticated, remote attacker can exploit this, via
    large OCSP Status Request extensions, to exhaust memory
    resources, resulting in a denial of service condition.
    (CVE-2016-6304)

  - A flaw exists in the SSL_peek() function in
    rec_layer_s3.c due to improper handling of empty
    records. An unauthenticated, remote attacker can exploit
    this, by triggering a zero-length record in an SSL_peek
    call, to cause an infinite loop, resulting in a denial
    of service condition. (CVE-2016-6305)

  - An out-of-bounds read error exists in the certificate
    parser that allows an unauthenticated, remote attacker
    to cause a denial of service via crafted certificate
    operations. (CVE-2016-6306)

  - A denial of service vulnerability exists in the
    state-machine implementation due to a failure to check
    for an excessive length before allocating memory. An
    unauthenticated, remote attacker can exploit this, via a
    crafted TLS message, to exhaust memory resources.
    (CVE-2016-6307)

Note that these issues only affects devices with J-Web or the SSL
service for JUNOScript enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10759");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20151203.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160128.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160503.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160922.txt");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10759.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_nested_array();

fixes["December 2015"]["CVEs"] =
  "CVE-2015-1794, CVE-2015-3193, CVE-2015-3194, CVE-2015-3195, CVE-2015-3196, CVE-2015-3197";
fixes["December 2015"]["Fixed Versions"] =
  "12.1X44-D60, 12.1X46-D45, 12.1X46-D51, 12.1X47-D35, 12.3R12, 12.3R13, 12.3X48-D25, 13.2X51-D40, 13.3R9, 14.1R7, 14.1X53-D35, 14.2R6, 15.1F5, 15.1R3, 15.1X49-D40, 15.1X53-D35, 16.1R1";

fixes["March 2016"]["CVEs"] =
  "CVE-2016-0705, CVE-2016-0798, CVE-2016-0797, CVE-2016-0799, CVE-2016-0702, CVE-2016-0703, CVE-2016-0704";
fixes["March 2016"]["Fixed Versions"] =
  "13.3R10, 14.1R8, 14.1X53-D40, 14.2R7, 15.1F5-S4, 15.1F6, 15.1R4, 15.1X49-D60, 15.1X53-D50, 16.1R1";

fixes["May 2016"]["CVEs"] =
  "CVE-2016-2105, CVE-2016-2106, CVE-2016-2108, CVE-2016-2109";
fixes["May 2016"]["Fixed Versions"] =
  "13.3R10, 14.1R9, 14.1X53-D40, 14.2R8, 15.1F5-S4, 15.1F6-S2, 15.1R4, 15.1X53-D50, 15.1X53-D60, 16.1R1";

fixes["September 2016"]["CVEs"] =
  "CVE-2016-2177, CVE-2016-2178, CVE-2016-2180, CVE-2016-2182, CVE-2016-2183, CVE-2016-6302, CVE-2016-6303, CVE-2016-6304, CVE-2016-6305, CVE-2016-6306, CVE-2016-6307";
fixes["September 2016"]["Fixed Versions"] =
  "12.1X46-D65, 13.3R10, 14.1R9, 14.1X55-D35, 14.2R8, 15.1F5-S5, 15.1R4-S5, 15.1R5, 15.1X49-D70, 16.1R3";

report = junos_multi_check_and_report(ver:ver, fixes:fixes);
if (isnull(report)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

# Configuration check: HTTPS or XNM-SSL must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set system services web-management https interface", # HTTPS
    "^set system services xnm-ssl" # SSL Service for JUNOScript (XNM-SSL)
  );
  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }
  if (override) audit(AUDIT_HOST_NOT,
    'affected because J-Web and SSL Service for JUNOScript (XNM-SSL) are not enabled');
}

extra = junos_caveat(override);
if (report_verbosity > 0)
  extra = report + junos_caveat(override);

security_report_v4(port:0, extra:extra, severity:SECURITY_HOLE);
