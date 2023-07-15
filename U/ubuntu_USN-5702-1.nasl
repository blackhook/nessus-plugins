##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5702-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166561);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-32221",
    "CVE-2022-35260",
    "CVE-2022-42915",
    "CVE-2022-42916"
  );
  script_xref(name:"USN", value:"5702-1");
  script_xref(name:"IAVA", value:"2022-A-0451-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : curl vulnerabilities (USN-5702-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5702-1 advisory.

  - curl before 7.86.0 has a double free. If curl is told to use an HTTP proxy for a transfer with a non-
    HTTP(S) URL, it sets up the connection to the remote server by issuing a CONNECT request to the proxy, and
    then tunnels the rest of the protocol through. An HTTP proxy might refuse this request (HTTP proxies often
    only allow outgoing connections to specific port numbers, like 443 for HTTPS) and instead return a non-200
    status code to the client. Due to flaws in the error/cleanup handling, this could trigger a double free in
    curl if one of the following schemes were used in the URL for the transfer: dict, gopher, gophers, ldap,
    ldaps, rtmp, rtmps, or telnet. The earliest affected version is 7.77.0. (CVE-2022-42915)

  - When doing HTTP(S) transfers, libcurl might erroneously use the read callback (`CURLOPT_READFUNCTION`) to
    ask for data to send, even when the `CURLOPT_POSTFIELDS` option has been set, if the same handle
    previously was used to issue a `PUT` request which used that callback. This flaw may surprise the
    application and cause it to misbehave and either send off the wrong data or use memory after free or
    similar in the subsequent `POST` request. The problem exists in the logic for a reused handle when it is
    changed from a PUT to a POST. (CVE-2022-32221)

  - curl can be told to parse a `.netrc` file for credentials. If that file endsin a line with 4095
    consecutive non-white space letters and no newline, curlwould first read past the end of the stack-based
    buffer, and if the readworks, write a zero byte beyond its boundary.This will in most cases cause a
    segfault or similar, but circumstances might also cause different outcomes.If a malicious user can provide
    a custom netrc file to an application or otherwise affect its contents, this flaw could be used as denial-
    of-service. (CVE-2022-35260)

  - In curl before 7.86.0, the HSTS check could be bypassed to trick it into staying with HTTP. Using its HSTS
    support, curl can be instructed to use HTTPS directly (instead of using an insecure cleartext HTTP step)
    even when HTTP is provided in the URL. This mechanism could be bypassed if the host name in the given URL
    uses IDN characters that get replaced with ASCII counterparts as part of the IDN conversion, e.g., using
    the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop of U+002E (.).
    The earliest affected version is 7.77.0 2021-05-26. (CVE-2022-42916)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5702-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32221");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/26");

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
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'curl', 'pkgver': '7.58.0-2ubuntu3.21'},
    {'osver': '18.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.58.0-2ubuntu3.21'},
    {'osver': '18.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.58.0-2ubuntu3.21'},
    {'osver': '18.04', 'pkgname': 'libcurl4', 'pkgver': '7.58.0-2ubuntu3.21'},
    {'osver': '18.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.58.0-2ubuntu3.21'},
    {'osver': '18.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.58.0-2ubuntu3.21'},
    {'osver': '18.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.58.0-2ubuntu3.21'},
    {'osver': '20.04', 'pkgname': 'curl', 'pkgver': '7.68.0-1ubuntu2.14'},
    {'osver': '20.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.68.0-1ubuntu2.14'},
    {'osver': '20.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.68.0-1ubuntu2.14'},
    {'osver': '20.04', 'pkgname': 'libcurl4', 'pkgver': '7.68.0-1ubuntu2.14'},
    {'osver': '20.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.68.0-1ubuntu2.14'},
    {'osver': '20.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.68.0-1ubuntu2.14'},
    {'osver': '20.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.68.0-1ubuntu2.14'},
    {'osver': '22.04', 'pkgname': 'curl', 'pkgver': '7.81.0-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.81.0-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.81.0-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'libcurl4', 'pkgver': '7.81.0-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.81.0-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.81.0-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.81.0-1ubuntu1.6'},
    {'osver': '22.10', 'pkgname': 'curl', 'pkgver': '7.85.0-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.85.0-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libcurl3-nss', 'pkgver': '7.85.0-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libcurl4', 'pkgver': '7.85.0-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.85.0-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.85.0-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.85.0-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl3-gnutls / libcurl3-nss / libcurl4 / etc');
}
