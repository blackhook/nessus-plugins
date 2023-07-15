#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124999);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2009-2409",
    "CVE-2010-0433",
    "CVE-2013-0166",
    "CVE-2014-0224",
    "CVE-2014-3470",
    "CVE-2014-3506",
    "CVE-2014-3508",
    "CVE-2014-3510",
    "CVE-2014-3570",
    "CVE-2015-0204",
    "CVE-2015-0287",
    "CVE-2015-0289",
    "CVE-2016-0704",
    "CVE-2017-3735",
    "CVE-2017-3737",
    "CVE-2017-3738",
    "CVE-2018-0495",
    "CVE-2018-0732",
    "CVE-2018-0737",
    "CVE-2018-0739"
  );
  script_bugtraq_id(
    29330,
    57755,
    60268,
    67898,
    67899,
    69075,
    69076,
    69082,
    71936,
    71939,
    73227,
    73231
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : openssl (EulerOS-SA-2019-1546)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - Libgcrypt before 1.7.10 and 1.8.x before 1.8.3 allows a
    memory-cache side-channel attack on ECDSA signatures
    that can be mitigated through the use of blinding
    during the signing process in the _gcry_ecc_ecdsa_sign
    function in cipher/ecc-ecdsa.c, aka the Return Of the
    Hidden Number Problem or ROHNP. To discover an ECDSA
    key, the attacker needs access to either the local
    machine or a different virtual machine on the same
    physical host.(CVE-2018-0495)

  - OpenSSL before 0.9.8y, 1.0.0 before 1.0.0k, and 1.0.1
    before 1.0.1d does not properly perform signature
    verification for OCSP responses, which allows remote
    OCSP servers to cause a denial of service (NULL pointer
    dereference and application crash) via an invalid
    key.(CVE-2013-0166)

  - OpenSSL 1.0.2 (starting from version 1.0.2b) introduced
    an 'error state' mechanism. The intent was that if a
    fatal error occurred during a handshake then OpenSSL
    would move into the error state and would immediately
    fail if you attempted to continue the handshake. This
    works as designed for the explicit handshake functions
    (SSL_do_handshake(), SSL_accept() and SSL_connect()),
    however due to a bug it does not work correctly if
    SSL_read() or SSL_write() is called directly. In that
    scenario, if the handshake fails then a fatal error
    will be returned in the initial function call. If
    SSL_read()/SSL_write() is subsequently called by the
    application for the same SSL object then it will
    succeed and the data is passed without being
    decrypted/encrypted directly from the SSL/TLS record
    layer. In order to exploit this issue an application
    bug would have to be present that resulted in a call to
    SSL_read()/SSL_write() being issued after having
    already received a fatal error. OpenSSL version
    1.0.2b-1.0.2m are affected. Fixed in OpenSSL 1.0.2n.
    OpenSSL 1.1.0 is not affected.(CVE-2017-3737)

  - An out-of-bounds write flaw was found in the way
    OpenSSL reused certain ASN.1 structures. A remote
    attacker could possibly use a specially crafted ASN.1
    structure that, when parsed by an application, would
    cause that application to crash.(CVE-2015-0287)

  - It was found that OpenSSL clients and servers could be
    forced, via a specially crafted handshake packet, to
    use weak keying material for communication. A
    man-in-the-middle attacker could use this flaw to
    decrypt and modify traffic between a client and a
    server.(CVE-2014-0224)

  - There is an overflow bug in the AVX2 Montgomery
    multiplication procedure used in exponentiation with
    1024-bit moduli. No EC algorithms are affected.
    Analysis suggests that attacks against RSA and DSA as a
    result of this defect would be very difficult to
    perform and are not believed likely. Attacks against
    DH1024 are considered just feasible, because most of
    the work necessary to deduce information about a
    private key may be performed offline. The amount of
    resources required for such an attack would be
    significant. However, for an attack on TLS to be
    meaningful, the server would have to share the DH1024
    private key among multiple clients, which is no longer
    an option since CVE-2016-0701. This only affects
    processors that support the AVX2 but not ADX extensions
    like Intel Haswell (4th generation). Note: The impact
    from this issue is similar to CVE-2017-3736,
    CVE-2017-3732 and CVE-2015-3193. OpenSSL version
    1.0.2-1.0.2m and 1.1.0-1.1.0g are affected. Fixed in
    OpenSSL 1.0.2n. Due to the low severity of this issue
    we are not issuing a new release of OpenSSL 1.1.0 at
    this time. The fix will be included in OpenSSL 1.1.0h
    when it becomes available. The fix is also available in
    commit e502cc86d in the OpenSSL git
    repository.(CVE-2017-3738)

  - The ssl3_send_client_key_exchange function in s3_clnt.c
    in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and
    1.0.1 before 1.0.1h, when an anonymous ECDH cipher
    suite is used, allows remote attackers to cause a
    denial of service (NULL pointer dereference and client
    crash) by triggering a NULL certificate
    value.(CVE-2014-3470)

  - It was discovered that the SSLv2 protocol
    implementation in OpenSSL did not properly implement
    the Bleichenbacher protection for export cipher suites.
    An attacker could use a SSLv2 server using OpenSSL as a
    Bleichenbacher oracle.(CVE-2016-0704)

  - A NULL pointer dereference flaw was found in the way
    OpenSSL performed a handshake when using the anonymous
    Diffie-Hellman (DH) key exchange. A malicious server
    could cause a DTLS client using OpenSSL to crash if
    that client had anonymous DH cipher suites
    enabled.(CVE-2014-3510)

  - While parsing an IPAddressFamily extension in an X.509
    certificate, it is possible to do a one-byte overread.
    This would result in an incorrect text display of the
    certificate. This bug has been present since 2006 and
    is present in all versions of OpenSSL before 1.0.2m and
    1.1.0g.(CVE-2017-3735)

  - The Network Security Services (NSS) library before
    3.12.3, as used in Firefox GnuTLS before 2.6.4 and
    2.7.4 OpenSSL 0.9.8 through 0.9.8k and other products
    support MD2 with X.509 certificates, which might allow
    remote attackers to spoof certificates by using MD2
    design flaws to generate a hash collision in less than
    brute-force time. NOTE: the scope of this issue is
    currently limited because the amount of computation
    required is still large.(CVE-2009-2409)

  - Constructed ASN.1 types with a recursive definition
    (such as can be found in PKCS7) could eventually exceed
    the stack given malicious input with excessive
    recursion. This could result in a Denial Of Service
    attack. There are no such structures used within
    SSL/TLS that come from untrusted sources so this is
    considered safe. Fixed in OpenSSL 1.1.0h (Affected
    1.1.0-1.1.0g). Fixed in OpenSSL 1.0.2o (Affected
    1.0.2b-1.0.2n).(CVE-2018-0739)

  - During key agreement in a TLS handshake using a DH(E)
    based ciphersuite a malicious server can send a very
    large prime value to the client. This will cause the
    client to spend an unreasonably long period of time
    generating a key for this prime resulting in a hang
    until the client has finished. This could be exploited
    in a Denial Of Service attack. Fixed in OpenSSL
    1.1.0i-dev (Affected 1.1.0-1.1.0h). Fixed in OpenSSL
    1.0.2p-dev (Affected 1.0.2-1.0.2o).(CVE-2018-0732)

  - A NULL pointer dereference was found in the way OpenSSL
    handled certain PKCS#7 inputs. An attacker able to make
    an application using OpenSSL verify, decrypt, or parse
    a specially crafted PKCS#7 input could cause that
    application to crash. TLS/SSL clients and servers using
    OpenSSL were not affected by this flaw.(CVE-2015-0289)

  - A flaw was discovered in the way OpenSSL handled DTLS
    packets. A remote attacker could use this flaw to cause
    a DTLS server or client using OpenSSL to crash or use
    excessive amounts of memory.(CVE-2014-3506)

  - The kssl_keytab_is_available function in ssl/kssl.c in
    OpenSSL before 0.9.8n, when Kerberos is enabled but
    Kerberos configuration files cannot be opened, does not
    check a certain return value, which allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and daemon crash) via SSL cipher
    negotiation, as demonstrated by a chroot installation
    of Dovecot or stunnel without Kerberos configuration
    files inside the chroot.(CVE-2010-0433)

  - It was discovered that OpenSSL would accept ephemeral
    RSA keys when using non-export RSA cipher suites. A
    malicious server could make a TLS/SSL client using
    OpenSSL use a weaker key exchange
    method.(CVE-2015-0204)

  - It was found that OpenSSL's BigNumber Squaring
    implementation could produce incorrect results under
    certain special conditions. This flaw could possibly
    affect certain OpenSSL library functionality, such as
    RSA blinding. Note that this issue occurred rarely and
    with a low probability, and there is currently no known
    way of exploiting it.(CVE-2014-3570)

  - It was discovered that the OBJ_obj2txt() function could
    fail to properly NUL-terminate its output. This could
    possibly cause an application using OpenSSL functions
    to format fields of X.509 certificates to disclose
    portions of its memory.(CVE-2014-3508)

  - OpenSSL RSA key generation was found to be vulnerable
    to cache side-channel attacks. An attacker with
    sufficient access to mount cache timing attacks during
    the RSA key generation process could recover parts of
    the private key.(CVE-2018-0737)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1546
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3aeefc06");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
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

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    severity   : SECURITY_WARNING,
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
