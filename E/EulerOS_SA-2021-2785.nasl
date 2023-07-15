#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155496);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-3735",
    "CVE-2017-3737",
    "CVE-2018-0732",
    "CVE-2018-0737",
    "CVE-2018-0739",
    "CVE-2019-1563",
    "CVE-2020-1971",
    "CVE-2021-3712",
    "CVE-2021-23840",
    "CVE-2021-23841"
  );
  script_xref(name:"IAVA", value:"2017-A-0327-S");
  script_xref(name:"IAVA", value:"2018-A-0133");
  script_xref(name:"IAVA", value:"2018-A-0117-S");
  script_xref(name:"IAVA", value:"2018-A-0121-S");
  script_xref(name:"IAVA", value:"2018-A-0033-S");
  script_xref(name:"IAVA", value:"2017-A-0358-S");
  script_xref(name:"IAVA", value:"2019-A-0021-S");
  script_xref(name:"IAVA", value:"2019-A-0023-S");
  script_xref(name:"IAVA", value:"2018-A-0277-S");
  script_xref(name:"IAVA", value:"2019-A-0020-S");
  script_xref(name:"IAVA", value:"2018-A-0336-S");
  script_xref(name:"IAVA", value:"2018-A-0091-S");
  script_xref(name:"IAVA", value:"2018-A-0226-S");
  script_xref(name:"IAVA", value:"2018-A-0225-S");
  script_xref(name:"IAVA", value:"2018-A-0229-S");
  script_xref(name:"IAVA", value:"2018-A-0335-S");
  script_xref(name:"IAVA", value:"2019-A-0303-S");
  script_xref(name:"IAVA", value:"2020-A-0566-S");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0196");
  script_xref(name:"IAVA", value:"2021-A-0328");
  script_xref(name:"IAVA", value:"2021-A-0038");
  script_xref(name:"IAVA", value:"2021-A-0480");
  script_xref(name:"IAVA", value:"2021-A-0103-S");
  script_xref(name:"IAVA", value:"2021-A-0195");
  script_xref(name:"IAVA", value:"2021-A-0395-S");
  script_xref(name:"IAVA", value:"2021-A-0487");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"EulerOS Virtualization 2.9.0 : shim (EulerOS-SA-2021-2785)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the shim package installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - While parsing an IPAddressFamily extension in an X.509 certificate, it is possible to do a one-byte
    overread. This would result in an incorrect text display of the certificate. This bug has been present
    since 2006 and is present in all versions of OpenSSL before 1.0.2m and 1.1.0g. (CVE-2017-3735)

  - OpenSSL 1.0.2 (starting from version 1.0.2b) introduced an 'error state' mechanism. The intent was that if
    a fatal error occurred during a handshake then OpenSSL would move into the error state and would
    immediately fail if you attempted to continue the handshake. This works as designed for the explicit
    handshake functions (SSL_do_handshake(), SSL_accept() and SSL_connect()), however due to a bug it does not
    work correctly if SSL_read() or SSL_write() is called directly. In that scenario, if the handshake fails
    then a fatal error will be returned in the initial function call. If SSL_read()/SSL_write() is
    subsequently called by the application for the same SSL object then it will succeed and the data is passed
    without being decrypted/encrypted directly from the SSL/TLS record layer. In order to exploit this issue
    an application bug would have to be present that resulted in a call to SSL_read()/SSL_write() being issued
    after having already received a fatal error. OpenSSL version 1.0.2b-1.0.2m are affected. Fixed in OpenSSL
    1.0.2n. OpenSSL 1.1.0 is not affected. (CVE-2017-3737)

  - During key agreement in a TLS handshake using a DH(E) based ciphersuite a malicious server can send a very
    large prime value to the client. This will cause the client to spend an unreasonably long period of time
    generating a key for this prime resulting in a hang until the client has finished. This could be exploited
    in a Denial Of Service attack. Fixed in OpenSSL 1.1.0i-dev (Affected 1.1.0-1.1.0h). Fixed in OpenSSL
    1.0.2p-dev (Affected 1.0.2-1.0.2o). (CVE-2018-0732)

  - The OpenSSL RSA Key generation algorithm has been shown to be vulnerable to a cache timing side channel
    attack. An attacker with sufficient access to mount cache timing attacks during the RSA key generation
    process could recover the private key. Fixed in OpenSSL 1.1.0i-dev (Affected 1.1.0-1.1.0h). Fixed in
    OpenSSL 1.0.2p-dev (Affected 1.0.2b-1.0.2o). (CVE-2018-0737)

  - Constructed ASN.1 types with a recursive definition (such as can be found in PKCS7) could eventually
    exceed the stack given malicious input with excessive recursion. This could result in a Denial Of Service
    attack. There are no such structures used within SSL/TLS that come from untrusted sources so this is
    considered safe. Fixed in OpenSSL 1.1.0h (Affected 1.1.0-1.1.0g). Fixed in OpenSSL 1.0.2o (Affected
    1.0.2b-1.0.2n). (CVE-2018-0739)

  - In situations where an attacker receives automated notification of the success or failure of a decryption
    attempt an attacker, after sending a very large number of messages to be decrypted, can recover a
    CMS/PKCS7 transported encryption key or decrypt any RSA encrypted message that was encrypted with the
    public RSA key, using a Bleichenbacher padding oracle attack. Applications are not affected if they use a
    certificate together with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions to select the
    correct recipient info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL
    1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s). (CVE-2019-1563)

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
    OpenSSL's s_server, s_client and verify tools have support for the '-crl_download' option which implements
    automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an
    unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of
    EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will
    accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue.
    Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected
    1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w). (CVE-2020-1971)

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

  - ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a
    buffer holding the string data and a field holding the buffer length. This contrasts with normal C strings
    which are repesented as a buffer for the string data which is terminated with a NUL (0) byte. Although not
    a strict requirement, ASN.1 strings that are parsed using OpenSSL's own 'd2i' functions (and other similar
    parsing functions) as well as any string whose value has been set with the ASN1_STRING_set() function will
    additionally NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for
    applications to directly construct valid ASN1_STRING structures which do not NUL terminate the byte array
    by directly setting the 'data' and 'length' fields in the ASN1_STRING array. This can also happen by using
    the ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1 data have been found to
    assume that the ASN1_STRING byte array will be NUL terminated, even though this is not guaranteed for
    strings that have been directly constructed. Where an application requests an ASN.1 structure to be
    printed, and where that ASN.1 structure contains ASN1_STRINGs that have been directly constructed by the
    application without NUL terminating the 'data' field, then a read buffer overrun can occur. The same thing
    can also occur during name constraints processing of certificates (for example if a certificate has been
    directly constructed by the application instead of loading it via the OpenSSL parsing functions, and the
    certificate contains non NUL terminated ASN1_STRING structures). It can also occur in the
    X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions. If a malicious actor can cause an
    application to directly construct an ASN1_STRING and then process it through one of the affected OpenSSL
    functions then this issue could be hit. This might result in a crash (causing a Denial of Service attack).
    It could also result in the disclosure of private memory contents (such as private keys, or sensitive
    plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected
    1.0.2-1.0.2y). (CVE-2021-3712)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2785
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c20c7c2");
  script_set_attribute(attribute:"solution", value:
"Update the affected shim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:shim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "shim-15-19.h7.eulerosv2r9"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "shim");
}
