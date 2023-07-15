#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5021-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156918);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-22898", "CVE-2021-22925");
  script_xref(name:"USN", value:"5021-2");
  script_xref(name:"IAVA", value:"2021-A-0437-S");
  script_xref(name:"IAVA", value:"2021-A-0352-S");

  script_name(english:"Ubuntu 16.04 LTS : curl vulnerability (USN-5021-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5021-2 advisory.

  - curl 7.7 through 7.76.1 suffers from an information disclosure when the `-t` command line option, known as
    `CURLOPT_TELNETOPTIONS` in libcurl, is used to send variable=content pairs to TELNET servers. Due to a
    flaw in the option parser for sending NEW_ENV variables, libcurl could be made to pass on uninitialized
    data from a stack based buffer to the server, resulting in potentially revealing sensitive internal
    information to the server using a clear-text network protocol. (CVE-2021-22898)

  - curl supports the `-t` command line option, known as `CURLOPT_TELNETOPTIONS`in libcurl. This rarely used
    option is used to send variable=content pairs toTELNET servers.Due to flaw in the option parser for
    sending `NEW_ENV` variables, libcurlcould be made to pass on uninitialized data from a stack based buffer
    to theserver. Therefore potentially revealing sensitive internal information to theserver using a clear-
    text network protocol.This could happen because curl did not call and use sscanf() correctly whenparsing
    the string provided by the application. (CVE-2021-22925)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5021-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22925");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '16.04', 'pkgname': 'curl', 'pkgver': '7.47.0-1ubuntu2.19+esm3'},
    {'osver': '16.04', 'pkgname': 'libcurl3', 'pkgver': '7.47.0-1ubuntu2.19+esm3'},
    {'osver': '16.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.47.0-1ubuntu2.19+esm3'},
    {'osver': '16.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.47.0-1ubuntu2.19+esm3'},
    {'osver': '16.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.47.0-1ubuntu2.19+esm3'},
    {'osver': '16.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.47.0-1ubuntu2.19+esm3'},
    {'osver': '16.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.47.0-1ubuntu2.19+esm3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl3 / libcurl3-gnutls / libcurl3-nss / libcurl4-gnutls-dev / etc');
}
