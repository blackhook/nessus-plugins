##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5474-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161982);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2019-20637",
    "CVE-2020-11653",
    "CVE-2021-36740",
    "CVE-2022-23959"
  );
  script_xref(name:"USN", value:"5474-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : Varnish Cache vulnerabilities (USN-5474-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5474-1 advisory.

  - An issue was discovered in Varnish Cache before 6.0.5 LTS, 6.1.x and 6.2.x before 6.2.2, and 6.3.x before
    6.3.1. It does not clear a pointer between the handling of one client request and the next request within
    the same connection. This sometimes causes information to be disclosed from the connection workspace, such
    as data structures associated with previous requests within this connection or VCL-related temporary
    headers. (CVE-2019-20637)

  - An issue was discovered in Varnish Cache before 6.0.6 LTS, 6.1.x and 6.2.x before 6.2.3, and 6.3.x before
    6.3.2. It occurs when communication with a TLS termination proxy uses PROXY version 2. There can be an
    assertion failure and daemon restart, which causes a performance loss. (CVE-2020-11653)

  - Varnish Cache, with HTTP/2 enabled, allows request smuggling and VCL authorization bypass via a large
    Content-Length header for a POST request. This affects Varnish Enterprise 6.0.x before 6.0.8r3, and
    Varnish Cache 5.x and 6.x before 6.5.2, 6.6.x before 6.6.1, and 6.0 LTS before 6.0.8. (CVE-2021-36740)

  - In Varnish Cache before 6.6.2 and 7.x before 7.0.2, Varnish Cache 6.0 LTS before 6.0.10, and and Varnish
    Enterprise (Cache Plus) 4.1.x before 4.1.11r6 and 6.0.x before 6.0.9r4, request smuggling can occur for
    HTTP/1 connections. (CVE-2022-23959)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5474-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23959");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvarnishapi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvarnishapi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvarnishapi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:varnish");
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
    {'osver': '18.04', 'pkgname': 'libvarnishapi-dev', 'pkgver': '5.2.1-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libvarnishapi1', 'pkgver': '5.2.1-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'varnish', 'pkgver': '5.2.1-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libvarnishapi-dev', 'pkgver': '6.2.1-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libvarnishapi2', 'pkgver': '6.2.1-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'varnish', 'pkgver': '6.2.1-2ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libvarnishapi-dev', 'pkgver': '6.5.2-1ubuntu0.2'},
    {'osver': '21.10', 'pkgname': 'libvarnishapi2', 'pkgver': '6.5.2-1ubuntu0.2'},
    {'osver': '21.10', 'pkgname': 'varnish', 'pkgver': '6.5.2-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libvarnishapi-dev', 'pkgver': '6.6.1-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libvarnishapi2', 'pkgver': '6.6.1-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'varnish', 'pkgver': '6.6.1-1ubuntu0.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvarnishapi-dev / libvarnishapi1 / libvarnishapi2 / varnish');
}
