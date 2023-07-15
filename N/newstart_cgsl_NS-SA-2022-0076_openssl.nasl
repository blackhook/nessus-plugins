#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0076. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167451);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id("CVE-2021-3712", "CVE-2022-0778", "CVE-2022-2078");
  script_xref(name:"IAVA", value:"2021-A-0395-S");
  script_xref(name:"IAVA", value:"2022-A-0121-S");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : openssl Multiple Vulnerabilities (NS-SA-2022-0076)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has openssl packages installed that are affected
by multiple vulnerabilities:

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
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0076");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3712");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-0778");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-2078");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL openssl packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3712");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/14");

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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'openssl-1.0.2k-25.el7_9.cgslv5.0.2.g9ca31f7.lite',
    'openssl-crypto-1.0.2k-25.el7_9.cgslv5.0.2.g9ca31f7.lite',
    'openssl-debuginfo-1.0.2k-25.el7_9.cgslv5.0.2.g9ca31f7.lite',
    'openssl-devel-1.0.2k-25.el7_9.cgslv5.0.2.g9ca31f7.lite',
    'openssl-libs-1.0.2k-25.el7_9.cgslv5.0.2.g9ca31f7.lite',
    'openssl-perl-1.0.2k-25.el7_9.cgslv5.0.2.g9ca31f7.lite',
    'openssl-static-1.0.2k-25.el7_9.cgslv5.0.2.g9ca31f7.lite'
  ],
  'CGSL MAIN 5.04': [
    'openssl-1.0.2k-25.el7_9.cgslv5.0.1.gf346a68',
    'openssl-debuginfo-1.0.2k-25.el7_9.cgslv5.0.1.gf346a68',
    'openssl-devel-1.0.2k-25.el7_9.cgslv5.0.1.gf346a68',
    'openssl-libs-1.0.2k-25.el7_9.cgslv5.0.1.gf346a68',
    'openssl-perl-1.0.2k-25.el7_9.cgslv5.0.1.gf346a68',
    'openssl-static-1.0.2k-25.el7_9.cgslv5.0.1.gf346a68'
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
