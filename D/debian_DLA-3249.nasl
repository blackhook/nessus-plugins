#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3249. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169300);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/26");

  script_cve_id(
    "CVE-2019-16910",
    "CVE-2019-18222",
    "CVE-2020-10932",
    "CVE-2020-10941",
    "CVE-2020-16150",
    "CVE-2020-36421",
    "CVE-2020-36422",
    "CVE-2020-36423",
    "CVE-2020-36424",
    "CVE-2020-36425",
    "CVE-2020-36426",
    "CVE-2020-36475",
    "CVE-2020-36476",
    "CVE-2020-36478",
    "CVE-2021-24119",
    "CVE-2021-43666",
    "CVE-2021-44732",
    "CVE-2022-35409"
  );

  script_name(english:"Debian DLA-3249-1 : mbedtls - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3249 advisory.

  - Arm Mbed TLS before 2.19.0 and Arm Mbed Crypto before 2.0.0, when deterministic ECDSA is enabled, use an
    RNG with insufficient entropy for blinding, which might allow an attacker to recover a private key via
    side-channel attacks if a victim signs the same message many times. (For Mbed TLS, the fix is also
    available in versions 2.7.12 and 2.16.3.) (CVE-2019-16910)

  - The ECDSA signature implementation in ecdsa.c in Arm Mbed Crypto 2.1 and Mbed TLS through 2.19.1 does not
    reduce the blinded scalar before computing the inverse, which allows a local attacker to recover the
    private key via side-channel attacks. (CVE-2019-18222)

  - An issue was discovered in Arm Mbed TLS before 2.16.6 and 2.7.x before 2.7.15. An attacker that can get
    precise enough side-channel measurements can recover the long-term ECDSA private key by (1) reconstructing
    the projective coordinate of the result of scalar multiplication by exploiting side channels in the
    conversion to affine coordinates; (2) using an attack described by Naccache, Smart, and Stern in 2003 to
    recover a few bits of the ephemeral scalar from those projective coordinates via several measurements; and
    (3) using a lattice attack to get from there to the long-term ECDSA private key used for the signatures.
    Typically an attacker would have sufficient access when attacking an SGX enclave and controlling the
    untrusted OS. (CVE-2020-10932)

  - Arm Mbed TLS before 2.16.5 allows attackers to obtain sensitive information (an RSA private key) by
    measuring cache usage during an import. (CVE-2020-10941)

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

  - An issue was discovered in Mbed TLS before 2.25.0 (and before 2.16.9 LTS and before 2.7.18 LTS). A NULL
    algorithm parameters entry looks identical to an array of REAL (size zero) and thus the certificate is
    considered valid. However, if the parameters do not match in any way, then the certificate should be
    considered invalid. (CVE-2020-36478)

  - In Trusted Firmware Mbed TLS 2.24.0, a side-channel vulnerability in base64 PEM file decoding allows
    system-level (administrator) attackers to obtain information about secret RSA keys via a controlled-
    channel and side-channel attack on software running in isolated environments that can be single stepped,
    especially Intel SGX. (CVE-2021-24119)

  - A Denial of Service vulnerability exists in mbed TLS 3.0.0 and earlier in the mbedtls_pkcs12_derivation
    function when an input password's length is 0. (CVE-2021-43666)

  - Mbed TLS before 3.0.1 has a double free in certain out-of-memory conditions, as demonstrated by an
    mbedtls_ssl_set_session() failure. (CVE-2021-44732)

  - An issue was discovered in Mbed TLS before 2.28.1 and 3.x before 3.2.0. In some configurations, an
    unauthenticated attacker can send an invalid ClientHello message to a DTLS server that causes a heap-based
    buffer over-read of up to 255 bytes. This can cause a server crash or possibly information disclosure
    based on error responses. Affected configurations have MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE enabled and
    MBEDTLS_SSL_IN_CONTENT_LEN less than a threshold that depends on the configuration: 258 bytes if using
    mbedtls_ssl_cookie_check, and possibly up to 571 bytes with a custom cookie check function.
    (CVE-2022-35409)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=941265");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mbedtls");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3249");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16910");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18222");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10932");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10941");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-16150");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36421");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36422");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36423");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36424");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36425");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36426");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36475");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36476");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36478");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-24119");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43666");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44732");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-35409");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/mbedtls");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mbedtls packages.

For Debian 10 buster, these problems have been fixed in version 2.16.9-0~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44732");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmbedcrypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmbedtls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmbedtls-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmbedtls12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmbedx509-0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libmbedcrypto3', 'reference': '2.16.9-0~deb10u1'},
    {'release': '10.0', 'prefix': 'libmbedtls-dev', 'reference': '2.16.9-0~deb10u1'},
    {'release': '10.0', 'prefix': 'libmbedtls-doc', 'reference': '2.16.9-0~deb10u1'},
    {'release': '10.0', 'prefix': 'libmbedtls12', 'reference': '2.16.9-0~deb10u1'},
    {'release': '10.0', 'prefix': 'libmbedx509-0', 'reference': '2.16.9-0~deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmbedcrypto3 / libmbedtls-dev / libmbedtls-doc / libmbedtls12 / etc');
}
