#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6142-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176745);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/07");

  script_cve_id("CVE-2020-11080");
  script_xref(name:"USN", value:"6142-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS : nghttp2 vulnerability (USN-6142-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-6142-1 advisory.

  - In nghttp2 before version 1.41.0, the overly large HTTP/2 SETTINGS frame payload causes denial of service.
    The proof of concept attack involves a malicious client constructing a SETTINGS frame with a length of
    14,400 bytes (2400 individual settings entries) over and over again. The attack causes the CPU to spike at
    100%. nghttp2 v1.41.0 fixes this vulnerability. There is a workaround to this vulnerability. Implement
    nghttp2_on_frame_recv_callback callback, and if received frame is SETTINGS frame and the number of
    settings entries are large (e.g., > 32), then drop the connection. (CVE-2020-11080)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6142-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11080");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnghttp2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnghttp2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nghttp2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nghttp2-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nghttp2-server");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libnghttp2-14', 'pkgver': '1.7.1-1ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libnghttp2-dev', 'pkgver': '1.7.1-1ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'nghttp2', 'pkgver': '1.7.1-1ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'nghttp2-client', 'pkgver': '1.7.1-1ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'nghttp2-proxy', 'pkgver': '1.7.1-1ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'nghttp2-server', 'pkgver': '1.7.1-1ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'libnghttp2-14', 'pkgver': '1.30.0-1ubuntu1+esm1'},
    {'osver': '18.04', 'pkgname': 'libnghttp2-dev', 'pkgver': '1.30.0-1ubuntu1+esm1'},
    {'osver': '18.04', 'pkgname': 'nghttp2', 'pkgver': '1.30.0-1ubuntu1+esm1'},
    {'osver': '18.04', 'pkgname': 'nghttp2-client', 'pkgver': '1.30.0-1ubuntu1+esm1'},
    {'osver': '18.04', 'pkgname': 'nghttp2-proxy', 'pkgver': '1.30.0-1ubuntu1+esm1'},
    {'osver': '18.04', 'pkgname': 'nghttp2-server', 'pkgver': '1.30.0-1ubuntu1+esm1'},
    {'osver': '20.04', 'pkgname': 'libnghttp2-14', 'pkgver': '1.40.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libnghttp2-dev', 'pkgver': '1.40.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'nghttp2', 'pkgver': '1.40.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'nghttp2-client', 'pkgver': '1.40.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'nghttp2-proxy', 'pkgver': '1.40.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'nghttp2-server', 'pkgver': '1.40.0-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnghttp2-14 / libnghttp2-dev / nghttp2 / nghttp2-client / etc');
}
