#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6039-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174752);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2022-3996", "CVE-2023-0464", "CVE-2023-0466");
  script_xref(name:"USN", value:"6039-1");
  script_xref(name:"IAVA", value:"2022-A-0518-S");
  script_xref(name:"IAVA", value:"2023-A-0158");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 / 23.04 : OpenSSL vulnerabilities (USN-6039-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 / 23.04 host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-6039-1 advisory.

  - If an X.509 certificate contains a malformed policy constraint and policy processing is enabled, then a
    write lock will be taken twice recursively. On some operating systems (most widely: Windows) this results
    in a denial of service when the affected process hangs. Policy processing being enabled on a publicly
    facing server is not considered to be a common setup. Policy processing is enabled by passing the
    `-policy' argument to the command line utilities or by calling the `X509_VERIFY_PARAM_set1_policies()'
    function. Update (31 March 2023): The description of the policy processing enablement was corrected based
    on CVE-2023-0466. (CVE-2022-3996)

  - A security vulnerability has been identified in all supported versions of OpenSSL related to the
    verification of X.509 certificate chains that include policy constraints. Attackers may be able to exploit
    this vulnerability by creating a malicious certificate chain that triggers exponential use of
    computational resources, leading to a denial-of-service (DoS) attack on affected systems. Policy
    processing is disabled by default but can be enabled by passing the `-policy' argument to the command line
    utilities or by calling the `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0464)

  - The function X509_VERIFY_PARAM_add0_policy() is documented to implicitly enable the certificate policy
    check when doing certificate verification. However the implementation of the function does not enable the
    check which allows certificates with invalid or incorrect policies to pass the certificate verification.
    As suddenly enabling the policy check could break existing deployments it was decided to keep the existing
    behavior of the X509_VERIFY_PARAM_add0_policy() function. Instead the applications that require OpenSSL to
    perform certificate policy check need to use X509_VERIFY_PARAM_set1_policies() or explicitly enable the
    policy check by calling X509_VERIFY_PARAM_set_flags() with the X509_V_FLAG_POLICY_CHECK flag argument.
    Certificate policy checks are disabled by default in OpenSSL and are not commonly used by applications.
    (CVE-2023-0466)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6039-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04|22\.10|23\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libssl-dev', 'pkgver': '1.0.2g-1ubuntu4.20+esm7'},
    {'osver': '16.04', 'pkgname': 'libssl1.0.0', 'pkgver': '1.0.2g-1ubuntu4.20+esm7'},
    {'osver': '16.04', 'pkgname': 'openssl', 'pkgver': '1.0.2g-1ubuntu4.20+esm7'},
    {'osver': '18.04', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1-1ubuntu2.1~18.04.22'},
    {'osver': '18.04', 'pkgname': 'libssl1.0-dev', 'pkgver': '1.0.2n-1ubuntu5.12'},
    {'osver': '18.04', 'pkgname': 'libssl1.0.0', 'pkgver': '1.0.2n-1ubuntu5.12'},
    {'osver': '18.04', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1-1ubuntu2.1~18.04.22'},
    {'osver': '18.04', 'pkgname': 'openssl', 'pkgver': '1.1.1-1ubuntu2.1~18.04.22'},
    {'osver': '18.04', 'pkgname': 'openssl1.0', 'pkgver': '1.0.2n-1ubuntu5.12'},
    {'osver': '20.04', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1f-1ubuntu2.18'},
    {'osver': '20.04', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1f-1ubuntu2.18'},
    {'osver': '20.04', 'pkgname': 'openssl', 'pkgver': '1.1.1f-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'libssl-dev', 'pkgver': '3.0.2-0ubuntu1.9'},
    {'osver': '22.04', 'pkgname': 'libssl3', 'pkgver': '3.0.2-0ubuntu1.9'},
    {'osver': '22.04', 'pkgname': 'openssl', 'pkgver': '3.0.2-0ubuntu1.9'},
    {'osver': '22.10', 'pkgname': 'libssl-dev', 'pkgver': '3.0.5-2ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'libssl3', 'pkgver': '3.0.5-2ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'openssl', 'pkgver': '3.0.5-2ubuntu2.2'},
    {'osver': '23.04', 'pkgname': 'libssl-dev', 'pkgver': '3.0.8-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'libssl3', 'pkgver': '3.0.8-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'openssl', 'pkgver': '3.0.8-1ubuntu1.1'}
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
    severity   : SECURITY_WARNING,
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
