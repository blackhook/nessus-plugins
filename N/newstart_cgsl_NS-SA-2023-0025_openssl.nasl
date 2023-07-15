#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0025. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174068);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id(
    "CVE-2021-3712",
    "CVE-2021-23840",
    "CVE-2021-23841",
    "CVE-2022-0778",
    "CVE-2022-2078"
  );
  script_xref(name:"IAVA", value:"2021-A-0103-S");
  script_xref(name:"IAVA", value:"2021-A-0395-S");
  script_xref(name:"IAVA", value:"2022-A-0121-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : openssl Multiple Vulnerabilities (NS-SA-2023-0025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has openssl packages installed that are affected
by multiple vulnerabilities:

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
    a strict requirement, ASN.1 strings that are parsed using OpenSSL's own d2i functions (and other similar
    parsing functions) as well as any string whose value has been set with the ASN1_STRING_set() function will
    additionally NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for
    applications to directly construct valid ASN1_STRING structures which do not NUL terminate the byte array
    by directly setting the data and length fields in the ASN1_STRING array. This can also happen by using
    the ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1 data have been found to
    assume that the ASN1_STRING byte array will be NUL terminated, even though this is not guaranteed for
    strings that have been directly constructed. Where an application requests an ASN.1 structure to be
    printed, and where that ASN.1 structure contains ASN1_STRINGs that have been directly constructed by the
    application without NUL terminating the data field, then a read buffer overrun can occur. The same thing
    can also occur during name constraints processing of certificates (for example if a certificate has been
    directly constructed by the application instead of loading it via the OpenSSL parsing functions, and the
    certificate contains non NUL terminated ASN1_STRING structures). It can also occur in the
    X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions. If a malicious actor can cause an
    application to directly construct an ASN1_STRING and then process it through one of the affected OpenSSL
    functions then this issue could be hit. This might result in a crash (causing a Denial of Service attack).
    It could also result in the disclosure of private memory contents (such as private keys, or sensitive
    plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected
    1.0.2-1.0.2y). (CVE-2021-3712)

  - The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778)

  - A vulnerability was found in the Linux kernel's nft_set_desc_concat_parse() function .This flaw allows an
    attacker to trigger a buffer overflow via nft_set_desc_concat_parse() , causing a denial of service and
    possibly to run code. (CVE-2022-2078)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0025");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23840");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23841");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3712");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-0778");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-2078");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL openssl packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3712");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.05" &&
    os_release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'openssl-1.0.2k-25.el7_9.cgslv5_5.0.2.gda82ce3.lite',
    'openssl-crypto-1.0.2k-25.el7_9.cgslv5_5.0.2.gda82ce3.lite',
    'openssl-debuginfo-1.0.2k-25.el7_9.cgslv5_5.0.2.gda82ce3.lite',
    'openssl-devel-1.0.2k-25.el7_9.cgslv5_5.0.2.gda82ce3.lite',
    'openssl-libs-1.0.2k-25.el7_9.cgslv5_5.0.2.gda82ce3.lite',
    'openssl-perl-1.0.2k-25.el7_9.cgslv5_5.0.2.gda82ce3.lite',
    'openssl-static-1.0.2k-25.el7_9.cgslv5_5.0.2.gda82ce3.lite'
  ],
  'CGSL MAIN 5.05': [
    'openssl-1.0.2k-25.el7_9.cgslv5_5.0.1.gdac5adc',
    'openssl-debuginfo-1.0.2k-25.el7_9.cgslv5_5.0.1.gdac5adc',
    'openssl-devel-1.0.2k-25.el7_9.cgslv5_5.0.1.gdac5adc',
    'openssl-libs-1.0.2k-25.el7_9.cgslv5_5.0.1.gdac5adc',
    'openssl-perl-1.0.2k-25.el7_9.cgslv5_5.0.1.gdac5adc',
    'openssl-static-1.0.2k-25.el7_9.cgslv5_5.0.1.gdac5adc'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl');
}
