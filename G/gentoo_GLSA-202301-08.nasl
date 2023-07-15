#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202301-08.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(169842);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id(
    "CVE-2020-16150",
    "CVE-2020-36421",
    "CVE-2020-36422",
    "CVE-2020-36423",
    "CVE-2020-36424",
    "CVE-2020-36425",
    "CVE-2020-36426",
    "CVE-2020-36475",
    "CVE-2020-36476",
    "CVE-2020-36477",
    "CVE-2020-36478",
    "CVE-2021-43666",
    "CVE-2021-44732",
    "CVE-2021-45450",
    "CVE-2022-35409"
  );

  script_name(english:"GLSA-202301-08 : Mbed TLS: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202301-08 (Mbed TLS: Multiple Vulnerabilities)

  - A Lucky 13 timing side channel in mbedtls_ssl_decrypt_buf in library/ssl_msg.c in Trusted Firmware Mbed
    TLS through 2.23.0 allows an attacker to recover secret key information. This affects CBC mode because of
    a computed time difference based on a padding length. (CVE-2020-16150)

  - An issue was discovered in Arm Mbed TLS before 2.23.0. Because of a side channel in modular
    exponentiation, an RSA private key used in a secure enclave could be disclosed. (CVE-2020-36421)

  - An issue was discovered in Arm Mbed TLS before 2.23.0. A side channel allows recovery of an ECC private
    key, related to mbedtls_ecp_check_pub_priv, mbedtls_pk_parse_key, mbedtls_pk_parse_keyfile,
    mbedtls_ecp_mul, and mbedtls_ecp_mul_restartable. (CVE-2020-36422)

  - An issue was discovered in Arm Mbed TLS before 2.23.0. A remote attacker can recover plaintext because a
    certain Lucky 13 countermeasure doesn't properly consider the case of a hardware accelerator.
    (CVE-2020-36423)

  - An issue was discovered in Arm Mbed TLS before 2.24.0. An attacker can recover a private key (for RSA or
    static Diffie-Hellman) via a side-channel attack against generation of base blinding/unblinding values.
    (CVE-2020-36424)

  - An issue was discovered in Arm Mbed TLS before 2.24.0. It incorrectly uses a revocationDate check when
    deciding whether to honor certificate revocation via a CRL. In some situations, an attacker can exploit
    this by changing the local clock. (CVE-2020-36425)

  - An issue was discovered in Arm Mbed TLS before 2.24.0. mbedtls_x509_crl_parse_der has a buffer over-read
    (of one byte). (CVE-2020-36426)

  - An issue was discovered in Mbed TLS before 2.25.0 (and before 2.16.9 LTS and before 2.7.18 LTS). The
    calculations performed by mbedtls_mpi_exp_mod are not limited; thus, supplying overly large parameters
    could lead to denial of service when generating Diffie-Hellman key pairs. (CVE-2020-36475)

  - An issue was discovered in Mbed TLS before 2.24.0 (and before 2.16.8 LTS and before 2.7.17 LTS). There is
    missing zeroization of plaintext buffers in mbedtls_ssl_read to erase unused application data from memory.
    (CVE-2020-36476)

  - An issue was discovered in Mbed TLS before 2.24.0. The verification of X.509 certificates when matching
    the expected common name (the cn argument of mbedtls_x509_crt_verify) with the actual certificate name is
    mishandled: when the subjecAltName extension is present, the expected name is compared to any name in that
    extension regardless of its type. This means that an attacker could impersonate a 4-byte or 16-byte domain
    by getting a certificate for the corresponding IPv4 or IPv6 address (this would require the attacker to
    control that IP address, though). (CVE-2020-36477)

  - An issue was discovered in Mbed TLS before 2.25.0 (and before 2.16.9 LTS and before 2.7.18 LTS). A NULL
    algorithm parameters entry looks identical to an array of REAL (size zero) and thus the certificate is
    considered valid. However, if the parameters do not match in any way, then the certificate should be
    considered invalid. (CVE-2020-36478)

  - A Denial of Service vulnerability exists in mbed TLS 3.0.0 and earlier in the mbedtls_pkcs12_derivation
    function when an input password's length is 0. (CVE-2021-43666)

  - Mbed TLS before 3.0.1 has a double free in certain out-of-memory conditions, as demonstrated by an
    mbedtls_ssl_set_session() failure. (CVE-2021-44732)

  - In Mbed TLS before 2.28.0 and 3.x before 3.1.0, psa_cipher_generate_iv and psa_cipher_encrypt allow policy
    bypass or oracle-based decryption when the output buffer is at memory locations accessible to an untrusted
    application. (CVE-2021-45450)

  - An issue was discovered in Mbed TLS before 2.28.1 and 3.x before 3.2.0. In some configurations, an
    unauthenticated attacker can send an invalid ClientHello message to a DTLS server that causes a heap-based
    buffer over-read of up to 255 bytes. This can cause a server crash or possibly information disclosure
    based on error responses. Affected configurations have MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE enabled and
    MBEDTLS_SSL_IN_CONTENT_LEN less than a threshold that depends on the configuration: 258 bytes if using
    mbedtls_ssl_cookie_check, and possibly up to 571 bytes with a custom cookie check function.
    (CVE-2022-35409)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202301-08");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=730752");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=740108");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=764317");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=778254");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=801376");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829660");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=857813");
  script_set_attribute(attribute:"solution", value:
"All Mbed TLS users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-libs/mbedtls-2.28.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44732");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mbedtls");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'net-libs/mbedtls',
    'unaffected' : make_list("ge 2.28.1"),
    'vulnerable' : make_list("lt 2.28.1")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mbed TLS');
}
