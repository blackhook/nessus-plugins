#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125000);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2007-3108",
    "CVE-2007-4995",
    "CVE-2008-5077",
    "CVE-2009-1378",
    "CVE-2009-1387",
    "CVE-2009-3245",
    "CVE-2009-3555",
    "CVE-2010-0742",
    "CVE-2010-4180",
    "CVE-2010-5298",
    "CVE-2013-0169",
    "CVE-2014-0195",
    "CVE-2014-0221",
    "CVE-2014-3505",
    "CVE-2014-3567",
    "CVE-2014-3572",
    "CVE-2015-0288",
    "CVE-2015-0292",
    "CVE-2015-1790",
    "CVE-2017-3736"
  );
  script_bugtraq_id(
    33150,
    35001,
    35417,
    36935,
    38562,
    40502,
    45164,
    57778,
    66801,
    67900,
    67901,
    69081,
    70586,
    71942,
    73196,
    73228,
    73237,
    75157
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"EulerOS Virtualization 3.0.1.0 : openssl (EulerOS-SA-2019-1547)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A NULL pointer dereference flaw was found in OpenSSL's
    X.509 certificate handling implementation. A specially
    crafted X.509 certificate could cause an application
    using OpenSSL to crash if the application attempted to
    convert the certificate to a certificate
    request.(CVE-2015-0288)

  - Off-by-one error in the DTLS implementation in OpenSSL
    0.9.8 before 0.9.8f allows remote attackers to execute
    arbitrary code via unspecified vectors.(CVE-2007-4995)

  - An integer underflow flaw, leading to a buffer
    overflow, was found in the way OpenSSL decoded
    malformed Base64-encoded inputs. An attacker able to
    make an application using OpenSSL decode a specially
    crafted Base64-encoded input (such as a PEM file) could
    use this flaw to cause the application to crash. Note:
    this flaw is not exploitable via the TLS/SSL protocol
    because the data being transferred is not
    Base64-encoded.(CVE-2015-0292)

  - OpenSSL before 0.9.8q, and 1.0.x before 1.0.0c, when
    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG is enabled,
    does not properly prevent modification of the
    ciphersuite in the session cache, which allows remote
    attackers to force the downgrade to an unintended
    cipher via vectors involving sniffing network traffic
    to discover a session identifier.(CVE-2010-4180)

  - OpenSSL before 0.9.8m does not check for a NULL return
    value from bn_wexpand function calls in (1)
    crypto/bn/bn_div.c, (2) crypto/bn/bn_gf2m.c, (3)
    crypto/ec/ec2_smpl.c, and (4) engines/e_ubsec.c, which
    has unspecified impact and context-dependent attack
    vectors.(CVE-2009-3245)

  - The Cryptographic Message Syntax (CMS) implementation
    in crypto/cms/cms_asn1.c in OpenSSL before 0.9.8o and
    1.x before 1.0.0a does not properly handle structures
    that contain OriginatorInfo, which allows
    context-dependent attackers to modify invalid memory
    locations or conduct double-free attacks, and possibly
    execute arbitrary code, via unspecified
    vectors.(CVE-2010-0742)

  - Race condition in the ssl3_read_bytes function in
    s3_pkt.c in OpenSSL through 1.0.1g, when
    SSL_MODE_RELEASE_BUFFERS is enabled, allows remote
    attackers to inject data across sessions or cause a
    denial of service (use-after-free and parsing error)
    via an SSL connection in a multithreaded
    environment.(CVE-2010-5298)

  - The BN_from_montgomery function in crypto/bn/bn_mont.c
    in OpenSSL 0.9.8e and earlier does not properly perform
    Montgomery multiplication, which might allow local
    users to conduct a side-channel attack and retrieve RSA
    private keys.(CVE-2007-3108)

  - A memory leak flaw was found in the way an OpenSSL
    handled failed session ticket integrity checks. A
    remote attacker could exhaust all available memory of
    an SSL/TLS or DTLS server by sending a large number of
    invalid session tickets to that server.(CVE-2014-3567)

  - It was discovered that OpenSSL would perform an ECDH
    key exchange with a non-ephemeral key even when the
    ephemeral ECDH cipher suite was selected. A malicious
    server could make a TLS/SSL client using OpenSSL use a
    weaker key exchange method than the one requested by
    the user.(CVE-2014-3572)

  - A denial of service flaw was found in the way OpenSSL
    handled certain DTLS ServerHello requests. A specially
    crafted DTLS handshake packet could cause a DTLS client
    using OpenSSL to crash.(CVE-2014-0221)

  - A NULL pointer dereference was found in the way OpenSSL
    handled certain PKCS#7 inputs. An attacker able to make
    an application using OpenSSL verify, decrypt, or parse
    a specially crafted PKCS#7 input could cause that
    application to crash. TLS/SSL clients and servers using
    OpenSSL were not affected by this flaw.(CVE-2015-1790)

  - The TLS protocol 1.1 and 1.2 and the DTLS protocol 1.0
    and 1.2, as used in OpenSSL, OpenJDK, PolarSSL, and
    other products, do not properly consider timing
    side-channel attacks on a MAC check requirement during
    the processing of malformed CBC padding, which allows
    remote attackers to conduct distinguishing attacks and
    plaintext-recovery attacks via statistical analysis of
    timing data for crafted packets, aka the 'Lucky
    Thirteen' issue.(CVE-2013-0169)

  - OpenSSL 0.9.8i and earlier does not properly check the
    return value from the EVP_VerifyFinal function, which
    allows remote attackers to bypass validation of the
    certificate chain via a malformed SSL/TLS signature for
    DSA and ECDSA keys.(CVE-2008-5077)

  - The TLS protocol, and the SSL protocol 3.0 and possibly
    earlier, as used in Microsoft Internet Information
    Services (IIS) 7.0, mod_ssl in the Apache HTTP Server
    2.2.14 and earlier, OpenSSL before 0.9.8l, GnuTLS 2.8.5
    and earlier, Mozilla Network Security Services (NSS)
    3.12.4 and earlier, multiple Cisco products, and other
    products, does not properly associate renegotiation
    handshakes with an existing connection, which allows
    man-in-the-middle attackers to insert data into HTTPS
    sessions, and possibly other types of sessions
    protected by TLS or SSL, by sending an unauthenticated
    request that is processed retroactively by a server in
    a post-renegotiation context, related to a 'plaintext
    injection' attack, aka the 'Project Mogul'
    issue.(CVE-2009-3555)

  - Multiple memory leaks in the
    dtls1_process_out_of_seq_message function in
    ssl/d1_both.c in OpenSSL 0.9.8k and earlier 0.9.8
    versions allow remote attackers to cause a denial of
    service (memory consumption) via DTLS records that (1)
    are duplicates or (2) have sequence numbers much
    greater than current sequence numbers, aka 'DTLS
    fragment handling memory leak.'(CVE-2009-1378)

  - The dtls1_retrieve_buffered_fragment function in
    ssl/d1_both.c in OpenSSL before 1.0.0 Beta 2 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and daemon crash) via an
    out-of-sequence DTLS handshake message, related to a
    'fragment bug.'(CVE-2009-1387)

  - There is a carry propagating bug in the x86_64
    Montgomery squaring procedure in OpenSSL before 1.0.2m
    and 1.1.0 before 1.1.0g. No EC algorithms are affected.
    Analysis suggests that attacks against RSA and DSA as a
    result of this defect would be very difficult to
    perform and are not believed likely. Attacks against DH
    are considered just feasible (although very difficult)
    because most of the work necessary to deduce
    information about a private key may be performed
    offline. The amount of resources required for such an
    attack would be very significant and likely only
    accessible to a limited number of attackers. An
    attacker would additionally need online access to an
    unpatched system using the target private key in a
    scenario with persistent DH parameters and a private
    key that is shared between multiple clients. This only
    affects processors that support the BMI1, BMI2 and ADX
    extensions like Intel Broadwell (5th generation) and
    later or AMD Ryzen.(CVE-2017-3736)

  - A flaw was discovered in the way OpenSSL handled DTLS
    packets. A remote attacker could use this flaw to cause
    a DTLS server or client using OpenSSL to crash or use
    excessive amounts of memory.(CVE-2014-3505)

  - The dtls1_reassemble_fragment function in d1_both.c in
    OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1
    before 1.0.1h does not properly validate fragment
    lengths in DTLS ClientHello messages, which allows
    remote attackers to execute arbitrary code or cause a
    denial of service (buffer overflow and application
    crash) via a long non-initial fragment.(CVE-2014-0195)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1547
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21e8b4ff");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 189, 310, 399);

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssl-1.0.2k-16.h5",
        "openssl-devel-1.0.2k-16.h5",
        "openssl-libs-1.0.2k-16.h5"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
