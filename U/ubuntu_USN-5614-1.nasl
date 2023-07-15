#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5614-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165205);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-3782");
  script_xref(name:"USN", value:"5614-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : Wayland vulnerability (USN-5614-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-5614-1 advisory.

  - An internal reference count is held on the buffer pool, incremented every time a new buffer is created
    from the pool. The reference count is maintained as an int; on LP64 systems this can cause the reference
    count to overflow if the client creates a large number of wl_shm buffer objects, or if it can coerce the
    server to create a large number of external references to the buffer storage. With the reference count
    overflowing, a use-after-free can be constructed on the wl_shm_pool tracking structure, where values may
    be incremented or decremented; it may also be possible to construct a limited oracle to leak 4 bytes of
    server-side memory to the attacking client at a time. (CVE-2021-3782)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5614-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3782");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwayland-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwayland-client0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwayland-cursor0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwayland-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwayland-egl-backend-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwayland-egl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwayland-server0");
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
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|22\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libwayland-bin', 'pkgver': '1.16.0-1ubuntu1.1~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libwayland-client0', 'pkgver': '1.16.0-1ubuntu1.1~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libwayland-cursor0', 'pkgver': '1.16.0-1ubuntu1.1~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libwayland-dev', 'pkgver': '1.16.0-1ubuntu1.1~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libwayland-egl-backend-dev', 'pkgver': '1.16.0-1ubuntu1.1~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libwayland-egl1', 'pkgver': '1.16.0-1ubuntu1.1~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libwayland-server0', 'pkgver': '1.16.0-1ubuntu1.1~18.04.4'},
    {'osver': '20.04', 'pkgname': 'libwayland-bin', 'pkgver': '1.18.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libwayland-client0', 'pkgver': '1.18.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libwayland-cursor0', 'pkgver': '1.18.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libwayland-dev', 'pkgver': '1.18.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libwayland-egl-backend-dev', 'pkgver': '1.18.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libwayland-egl1', 'pkgver': '1.18.0-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libwayland-server0', 'pkgver': '1.18.0-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libwayland-bin', 'pkgver': '1.20.0-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libwayland-client0', 'pkgver': '1.20.0-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libwayland-cursor0', 'pkgver': '1.20.0-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libwayland-dev', 'pkgver': '1.20.0-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libwayland-egl-backend-dev', 'pkgver': '1.20.0-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libwayland-egl1', 'pkgver': '1.20.0-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libwayland-server0', 'pkgver': '1.20.0-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwayland-bin / libwayland-client0 / libwayland-cursor0 / etc');
}
