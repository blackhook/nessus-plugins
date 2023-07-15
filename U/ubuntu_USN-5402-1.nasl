##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5402-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160502);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-1292",
    "CVE-2022-1343",
    "CVE-2022-1434",
    "CVE-2022-1473"
  );
  script_xref(name:"USN", value:"5402-1");
  script_xref(name:"IAVA", value:"2022-A-0186-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : OpenSSL vulnerabilities (USN-5402-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5402-1 advisory.

  - The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This
    script is distributed by some operating systems in a manner where it is automatically executed. On such
    operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of
    the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool.
    Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n).
    Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd). (CVE-2022-1292)

  - The function `OCSP_basic_verify` verifies the signer certificate on an OCSP response. In the case where
    the (non-default) flag OCSP_NOCHECKS is used then the response will be positive (meaning a successful
    verification) even in the case where the response signing certificate fails to verify. It is anticipated
    that most users of `OCSP_basic_verify` will not use the OCSP_NOCHECKS flag. In this case the
    `OCSP_basic_verify` function will return a negative value (indicating a fatal error) in the case of a
    certificate verification failure. The normal expected return value in this case would be 0. This issue
    also impacts the command line OpenSSL ocsp application. When verifying an ocsp response with the
    -no_cert_checks option the command line application will report that the verification is successful even
    though it has in fact failed. In this case the incorrect successful response will also be accompanied by
    error messages showing the failure and contradicting the apparently successful result. Fixed in OpenSSL
    3.0.3 (Affected 3.0.0,3.0.1,3.0.2). (CVE-2022-1343)

  - The OpenSSL 3.0 implementation of the RC4-MD5 ciphersuite incorrectly uses the AAD data as the MAC key.
    This makes the MAC key trivially predictable. An attacker could exploit this issue by performing a man-in-
    the-middle attack to modify data being sent from one endpoint to an OpenSSL 3.0 recipient such that the
    modified data would still pass the MAC integrity check. Note that data sent from an OpenSSL 3.0 endpoint
    to a non-OpenSSL 3.0 endpoint will always be rejected by the recipient and the connection will fail at
    that point. Many application protocols require data to be sent from the client to the server first.
    Therefore, in such a case, only an OpenSSL 3.0 server would be impacted when talking to a non-OpenSSL 3.0
    client. If both endpoints are OpenSSL 3.0 then the attacker could modify data being sent in both
    directions. In this case both clients and servers could be affected, regardless of the application
    protocol. Note that in the absence of an attacker this bug means that an OpenSSL 3.0 endpoint
    communicating with a non-OpenSSL 3.0 endpoint will fail to complete the handshake when using this
    ciphersuite. The confidentiality of data is not impacted by this issue, i.e. an attacker cannot decrypt
    data that has been encrypted using this ciphersuite - they can only modify it. In order for this attack to
    work both endpoints must legitimately negotiate the RC4-MD5 ciphersuite. This ciphersuite is not compiled
    by default in OpenSSL 3.0, and is not available within the default provider or the default ciphersuite
    list. This ciphersuite will never be used if TLSv1.3 has been negotiated. In order for an OpenSSL 3.0
    endpoint to use this ciphersuite the following must have occurred: 1) OpenSSL must have been compiled with
    the (non-default) compile time option enable-weak-ssl-ciphers 2) OpenSSL must have had the legacy provider
    explicitly loaded (either through application code or via configuration) 3) The ciphersuite must have been
    explicitly added to the ciphersuite list 4) The libssl security level must have been set to 0 (default is
    1) 5) A version of SSL/TLS below TLSv1.3 must have been negotiated 6) Both endpoints must negotiate the
    RC4-MD5 ciphersuite in preference to any others that both endpoints have in common Fixed in OpenSSL 3.0.3
    (Affected 3.0.0,3.0.1,3.0.2). (CVE-2022-1434)

  - The OPENSSL_LH_flush() function, which empties a hash table, contains a bug that breaks reuse of the
    memory occuppied by the removed hash table entries. This function is used when decoding certificates or
    keys. If a long lived process periodically decodes certificates or keys its memory usage will expand
    without bounds and the process might be terminated by the operating system causing a denial of service.
    Also traversing the empty hash table entries will take increasingly more time. Typically such long lived
    processes might be TLS clients or TLS servers configured to accept client certificate authentication. The
    function was added in the OpenSSL 3.0 version thus older releases are not affected by the issue. Fixed in
    OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). (CVE-2022-1473)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5402-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1292");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl1.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1-1ubuntu2.1~18.04.17'},
    {'osver': '18.04', 'pkgname': 'libssl1.0-dev', 'pkgver': '1.0.2n-1ubuntu5.9'},
    {'osver': '18.04', 'pkgname': 'libssl1.0.0', 'pkgver': '1.0.2n-1ubuntu5.9'},
    {'osver': '18.04', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1-1ubuntu2.1~18.04.17'},
    {'osver': '18.04', 'pkgname': 'openssl', 'pkgver': '1.1.1-1ubuntu2.1~18.04.17'},
    {'osver': '18.04', 'pkgname': 'openssl1.0', 'pkgver': '1.0.2n-1ubuntu5.9'},
    {'osver': '20.04', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1f-1ubuntu2.13'},
    {'osver': '20.04', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1f-1ubuntu2.13'},
    {'osver': '20.04', 'pkgname': 'openssl', 'pkgver': '1.1.1f-1ubuntu2.13'},
    {'osver': '21.10', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1l-1ubuntu1.3'},
    {'osver': '21.10', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1l-1ubuntu1.3'},
    {'osver': '21.10', 'pkgname': 'openssl', 'pkgver': '1.1.1l-1ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libssl-dev', 'pkgver': '3.0.2-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libssl3', 'pkgver': '3.0.2-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'openssl', 'pkgver': '3.0.2-0ubuntu1.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libssl-dev / libssl1.0-dev / libssl1.0.0 / libssl1.1 / libssl3 / etc');
}
