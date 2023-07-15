#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4504-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140645);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2019-1547",
    "CVE-2019-1551",
    "CVE-2019-1563",
    "CVE-2020-1968"
  );
  script_xref(name:"USN", value:"4504-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : OpenSSL vulnerabilities (USN-4504-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4504-1 advisory.

  - Normally in OpenSSL EC groups always have a co-factor present and this is used in side channel resistant
    code paths. However, in some cases, it is possible to construct a group using explicit parameters (instead
    of using a named curve). In those cases it is possible that such a group does not have the cofactor
    present. This can occur even where all the parameters match a known named curve. If such a curve is used
    then OpenSSL falls back to non-side channel resistant code paths which may result in full key recovery
    during an ECDSA signature operation. In order to be vulnerable an attacker would have to have the ability
    to time the creation of a large number of signatures where explicit parameters with no co-factor present
    are in use by an application using libcrypto. For the avoidance of doubt libssl is not vulnerable because
    explicit parameters are never used. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL
    1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s). (CVE-2019-1547)

  - There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit
    moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime
    RSA1536, and DSA1024 as a result of this defect would be very difficult to perform and are not believed
    likely. Attacks against DH512 are considered just feasible. However, for an attack the target would have
    to re-use the DH512 private key, which is not recommended anyway. Also applications directly using the low
    level API BN_mod_exp may be affected if they use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected
    1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected 1.0.2-1.0.2t). (CVE-2019-1551)

  - In situations where an attacker receives automated notification of the success or failure of a decryption
    attempt an attacker, after sending a very large number of messages to be decrypted, can recover a
    CMS/PKCS7 transported encryption key or decrypt any RSA encrypted message that was encrypted with the
    public RSA key, using a Bleichenbacher padding oracle attack. Applications are not affected if they use a
    certificate together with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions to select the
    correct recipient info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL
    1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s). (CVE-2019-1563)

  - The Raccoon attack exploits a flaw in the TLS specification which can lead to an attacker being able to
    compute the pre-master secret in connections which have used a Diffie-Hellman (DH) based ciphersuite. In
    such a case this would result in the attacker being able to eavesdrop on all encrypted communications sent
    over that TLS connection. The attack can only be exploited if an implementation re-uses a DH secret across
    multiple TLS connections. Note that this issue only impacts DH ciphersuites and not ECDH ciphersuites.
    This issue affects OpenSSL 1.0.2 which is out of support and no longer receiving public updates. OpenSSL
    1.1.1 is not vulnerable to this issue. Fixed in OpenSSL 1.0.2w (Affected 1.0.2-1.0.2v). (CVE-2020-1968)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4504-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrypto1.0.0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl1.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'libcrypto1.0.0-udeb', 'pkgver': '1.0.2g-1ubuntu4.17'},
    {'osver': '16.04', 'pkgname': 'libssl-dev', 'pkgver': '1.0.2g-1ubuntu4.17'},
    {'osver': '16.04', 'pkgname': 'libssl1.0.0', 'pkgver': '1.0.2g-1ubuntu4.17'},
    {'osver': '16.04', 'pkgname': 'libssl1.0.0-udeb', 'pkgver': '1.0.2g-1ubuntu4.17'},
    {'osver': '16.04', 'pkgname': 'openssl', 'pkgver': '1.0.2g-1ubuntu4.17'},
    {'osver': '18.04', 'pkgname': 'libcrypto1.0.0-udeb', 'pkgver': '1.0.2n-1ubuntu5.4'},
    {'osver': '18.04', 'pkgname': 'libssl1.0-dev', 'pkgver': '1.0.2n-1ubuntu5.4'},
    {'osver': '18.04', 'pkgname': 'libssl1.0.0', 'pkgver': '1.0.2n-1ubuntu5.4'},
    {'osver': '18.04', 'pkgname': 'libssl1.0.0-udeb', 'pkgver': '1.0.2n-1ubuntu5.4'},
    {'osver': '18.04', 'pkgname': 'openssl1.0', 'pkgver': '1.0.2n-1ubuntu5.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcrypto1.0.0-udeb / libssl-dev / libssl1.0-dev / libssl1.0.0 / etc');
}
