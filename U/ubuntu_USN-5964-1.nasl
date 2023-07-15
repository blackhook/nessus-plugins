#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5964-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173037);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/01");

  script_cve_id(
    "CVE-2023-27533",
    "CVE-2023-27534",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27538"
  );
  script_xref(name:"USN", value:"5964-1");
  script_xref(name:"IAVA", value:"2023-A-0153-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : curl vulnerabilities (USN-5964-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5964-1 advisory.

  - A vulnerability in input validation exists in curl <8.0 during communication using the TELNET protocol may
    allow an attacker to pass on maliciously crafted user name and telnet options during server negotiation.
    The lack of proper input scrubbing allows an attacker to send content or perform option negotiation
    without the application's intent. This vulnerability could be exploited if an application allows user
    input, thereby enabling attackers to execute arbitrary code on the system. (CVE-2023-27533)

  - A path traversal vulnerability exists in curl <8.0.0 SFTP implementation causes the tilde (~) character to
    be wrongly replaced when used as a prefix in the first path element, in addition to its intended use as
    the first element to indicate a path relative to the user's home directory. Attackers can exploit this
    flaw to bypass filtering or execute arbitrary code by crafting a path like /~2/foo while accessing a
    server with a specific user. (CVE-2023-27534)

  - An authentication bypass vulnerability exists in libcurl <8.0.0 in the FTP connection reuse feature that
    can result in wrong credentials being used during subsequent transfers. Previously created connections are
    kept in a connection pool for reuse if they match the current setup. However, certain FTP settings such as
    CURLOPT_FTP_ACCOUNT, CURLOPT_FTP_ALTERNATIVE_TO_USER, CURLOPT_FTP_SSL_CCC, and CURLOPT_USE_SSL were not
    included in the configuration match checks, causing them to match too easily. This could lead to libcurl
    using the wrong credentials when performing a transfer, potentially allowing unauthorized access to
    sensitive information. (CVE-2023-27535)

  - An authentication bypass vulnerability exists libcurl <8.0.0 in the connection reuse feature which can
    reuse previously established connections with incorrect user permissions due to a failure to check for
    changes in the CURLOPT_GSSAPI_DELEGATION option. This vulnerability affects krb5/kerberos/negotiate/GSSAPI
    transfers and could potentially result in unauthorized access to sensitive information. The safest option
    is to not reuse connections if the CURLOPT_GSSAPI_DELEGATION option has been changed. (CVE-2023-27536)

  - An authentication bypass vulnerability exists in libcurl v8.0.0 where it reuses a previously established
    SSH connection despite the fact that an SSH option was modified, which should have prevented reuse.
    libcurl maintains a pool of previously used connections to reuse them for subsequent transfers if the
    configurations match. However, two SSH settings were omitted from the configuration check, allowing them
    to match easily, potentially leading to the reuse of an inappropriate connection. (CVE-2023-27538)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5964-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27533");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-27534");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-openssl-dev");
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
if (! preg(pattern:"^(18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'curl', 'pkgver': '7.58.0-2ubuntu3.24'},
    {'osver': '18.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.58.0-2ubuntu3.24'},
    {'osver': '18.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.58.0-2ubuntu3.24'},
    {'osver': '18.04', 'pkgname': 'libcurl4', 'pkgver': '7.58.0-2ubuntu3.24'},
    {'osver': '18.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.58.0-2ubuntu3.24'},
    {'osver': '18.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.58.0-2ubuntu3.24'},
    {'osver': '18.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.58.0-2ubuntu3.24'},
    {'osver': '20.04', 'pkgname': 'curl', 'pkgver': '7.68.0-1ubuntu2.18'},
    {'osver': '20.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.68.0-1ubuntu2.18'},
    {'osver': '20.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.68.0-1ubuntu2.18'},
    {'osver': '20.04', 'pkgname': 'libcurl4', 'pkgver': '7.68.0-1ubuntu2.18'},
    {'osver': '20.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.68.0-1ubuntu2.18'},
    {'osver': '20.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.68.0-1ubuntu2.18'},
    {'osver': '20.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.68.0-1ubuntu2.18'},
    {'osver': '22.04', 'pkgname': 'curl', 'pkgver': '7.81.0-1ubuntu1.10'},
    {'osver': '22.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.81.0-1ubuntu1.10'},
    {'osver': '22.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.81.0-1ubuntu1.10'},
    {'osver': '22.04', 'pkgname': 'libcurl4', 'pkgver': '7.81.0-1ubuntu1.10'},
    {'osver': '22.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.81.0-1ubuntu1.10'},
    {'osver': '22.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.81.0-1ubuntu1.10'},
    {'osver': '22.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.81.0-1ubuntu1.10'},
    {'osver': '22.10', 'pkgname': 'curl', 'pkgver': '7.85.0-1ubuntu0.5'},
    {'osver': '22.10', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.85.0-1ubuntu0.5'},
    {'osver': '22.10', 'pkgname': 'libcurl3-nss', 'pkgver': '7.85.0-1ubuntu0.5'},
    {'osver': '22.10', 'pkgname': 'libcurl4', 'pkgver': '7.85.0-1ubuntu0.5'},
    {'osver': '22.10', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.85.0-1ubuntu0.5'},
    {'osver': '22.10', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.85.0-1ubuntu0.5'},
    {'osver': '22.10', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.85.0-1ubuntu0.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl3-gnutls / libcurl3-nss / libcurl4 / libcurl4-gnutls-dev / etc');
}
