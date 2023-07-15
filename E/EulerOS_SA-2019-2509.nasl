#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131662);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2014-0204",
    "CVE-2014-0221",
    "CVE-2014-3505",
    "CVE-2014-3506",
    "CVE-2014-3508",
    "CVE-2014-3510",
    "CVE-2014-3566",
    "CVE-2014-3570",
    "CVE-2014-8176",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-1790",
    "CVE-2015-4000",
    "CVE-2016-2178",
    "CVE-2016-2181",
    "CVE-2016-2183",
    "CVE-2017-3735"
  );
  script_bugtraq_id(
    67580,
    67901,
    69075,
    69076,
    69081,
    69082,
    70574,
    71939,
    73196,
    73227,
    73231,
    73237,
    74733,
    75157,
    75159
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"EulerOS 2.0 SP2 : openssl098e (EulerOS-SA-2019-2509)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl098e package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The OpenSSL toolkit provides support for secure
    communications between machines. OpenSSL includes a
    certificate management tool and shared libraries which
    provide various cryptographic algorithms and
    protocols.Security Fix(es):The TLS protocol 1.2 and
    earlier, when a DHE_EXPORT ciphersuite is enabled on a
    server but not on a client, does not properly convey a
    DHE_EXPORT choice, which allows man-in-the-middle
    attackers to conduct cipher-downgrade attacks by
    rewriting a ClientHello with DHE replaced by DHE_EXPORT
    and then rewriting a ServerHello with DHE_EXPORT
    replaced by DHE, aka the 'Logjam'
    issue.(CVE-2015-4000)The dsa_sign_setup function in
    crypto/dsa/dsa_ossl.c in OpenSSL through 1.0.2h does
    not properly ensure the use of constant-time
    operations, which makes it easier for local users to
    discover a DSA private key via a timing side-channel
    attack.(CVE-2016-2178)While parsing an IPAddressFamily
    extension in an X.509 certificate, it is possible to do
    a one-byte overread. This would result in an incorrect
    text display of the certificate. This bug has been
    present since 2006 and is present in all versions of
    OpenSSL before 1.0.2m and 1.1.0g.(CVE-2017-3735)The
    Anti-Replay feature in the DTLS implementation in
    OpenSSL before 1.1.0 mishandles early use of a new
    epoch number in conjunction with a large sequence
    number, which allows remote attackers to cause a denial
    of service (false-positive packet drops) via spoofed
    DTLS records, related to rec_layer_d1.c and
    ssl3_record.c.(CVE-2016-2181)The SSL protocol 3.0, as
    used in OpenSSL through 1.0.1i and other products, uses
    nondeterministic CBC padding, which makes it easier for
    man-in-the-middle attackers to obtain cleartext data
    via a padding-oracle attack, aka the 'POODLE'
    issue.(CVE-2014-3566)OpenStack Identity (Keystone)
    before 2014.1.1 does not properly handle when a role is
    assigned to a group that has the same ID as a user,
    which allows remote authenticated users to gain
    privileges that are assigned to a group with the same
    ID.(CVE-2014-0204)Double free vulnerability in
    d1_both.c in the DTLS implementation in OpenSSL 0.9.8
    before 0.9.8zb, 1.0.0 before 1.0.0n, and 1.0.1 before
    1.0.1i allows remote attackers to cause a denial of
    service (application crash) via crafted DTLS packets
    that trigger an error
    condition.(CVE-2014-3505)d1_both.c in the DTLS
    implementation in OpenSSL 0.9.8 before 0.9.8zb, 1.0.0
    before 1.0.0n, and 1.0.1 before 1.0.1i allows remote
    attackers to cause a denial of service (memory
    consumption) via crafted DTLS handshake messages that
    trigger memory allocations corresponding to large
    length values.(CVE-2014-3506)The BN_sqr implementation
    in OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and
    1.0.1 before 1.0.1k does not properly calculate the
    square of a BIGNUM value, which might make it easier
    for remote attackers to defeat cryptographic protection
    mechanisms via unspecified vectors, related to
    crypto/bn/asm/mips.pl, crypto/bn/asm/x86_64-gcc.c, and
    crypto/bn/bn_asm.c.(CVE-2014-3570)The OBJ_obj2txt
    function in crypto/objects/obj_dat.c in OpenSSL 0.9.8
    before 0.9.8zb, 1.0.0 before 1.0.0n, and 1.0.1 before
    1.0.1i, when pretty printing is used, does not ensure
    the presence of '\0' characters, which allows
    context-dependent attackers to obtain sensitive
    information from process stack memory by reading output
    from X509_name_oneline, X509_name_print_ex, and
    unspecified other functions.(CVE-2014-3508)The
    dtls1_clear_queues function in ssl/d1_lib.c in OpenSSL
    before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before
    1.0.1h frees data structures without considering that
    application data can arrive between a ChangeCipherSpec
    message and a Finished message, which allows remote
    DTLS peers to cause a denial of service (memory
    corruption and application crash) or possibly have
    unspecified other impact via unexpected application
    data.(CVE-2014-8176)The DES and Triple DES ciphers, as
    used in the TLS, SSH, and IPSec protocols and other
    protocols and products, have a birthday bound of
    approximately four billion blocks, which makes it
    easier for remote attackers to obtain cleartext data
    via a birthday attack against a long-duration encrypted
    session, as demonstrated by an HTTPS session using
    Triple DES in CBC mode, aka a 'Sweet32'
    attack.(CVE-2016-2183)The ASN1_item_ex_d2i function in
    crypto/asn1/tasn_dec.c in OpenSSL before 0.9.8zf, 1.0.0
    before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before
    1.0.2a does not reinitialize CHOICE and ADB data
    structures, which might allow attackers to cause a
    denial of service (invalid write operation and memory
    corruption) by leveraging an application that relies on
    ASN.1 structure reuse.(CVE-2015-0287)The
    dtls1_get_message_fragment function in d1_both.c in
    OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1
    before 1.0.1h allows remote attackers to cause a denial
    of service (recursion and client crash) via a DTLS
    hello message in an invalid DTLS
    handshake.(CVE-2014-0221)The
    ssl3_send_client_key_exchange function in s3_clnt.c in
    OpenSSL 0.9.8 before 0.9.8zb, 1.0.0 before 1.0.0n, and
    1.0.1 before 1.0.1i allows remote DTLS servers to cause
    a denial of service (NULL pointer dereference and
    client application crash) via a crafted handshake
    message in conjunction with a (1) anonymous DH or (2)
    anonymous ECDH ciphersuite.(CVE-2014-3510)The
    X509_to_X509_REQ function in crypto/x509/x509_req.c in
    OpenSSL before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1
    before 1.0.1m, and 1.0.2 before 1.0.2a might allow
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via an invalid
    certificate key.(CVE-2015-0288)The PKCS#7
    implementation in OpenSSL before 0.9.8zf, 1.0.0 before
    1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a
    does not properly handle a lack of outer ContentInfo,
    which allows attackers to cause a denial of service
    (NULL pointer dereference and application crash) by
    leveraging an application that processes arbitrary
    PKCS#7 data and providing malformed data with ASN.1
    encoding, related to crypto/pkcs7/pk7_doit.c and
    crypto/pkcs7/pk7_lib.c.(CVE-2015-0289)The
    PKCS7_dataDecodefunction in crypto/pkcs7/pk7_doit.c in
    OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1
    before 1.0.1n, and 1.0.2 before 1.0.2b allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via a PKCS#7 blob
    that uses ASN.1 encoding and lacks inner
    EncryptedContent data.(CVE-2015-1790)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2509
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0570d847");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl098e packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8176");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-2183");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl098e");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssl098e-0.9.8e-29.3.h17"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
