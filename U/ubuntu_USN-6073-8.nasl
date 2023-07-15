#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6073-8. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176243);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");
  script_xref(name:"USN", value:"6073-8");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 / 23.04 : Nova regression (USN-6073-8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 / 23.04 host has packages installed that are affected by a vulnerability
as referenced in the USN-6073-8 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6073-8");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-ajax-console-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-os-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-os-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-cells");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-ironic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-novncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-serialproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-spiceproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-nova");
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
if (! preg(pattern:"^(20\.04|22\.04|22\.10|23\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-api', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-api-metadata', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-cells', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-common', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-compute', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-compute-xen', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-conductor', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-novncproxy', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-scheduler', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-serialproxy', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'nova-volume', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'python3-nova', 'pkgver': '2:21.2.4-0ubuntu2.5'},
    {'osver': '22.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-api', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-api-metadata', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-cells', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-common', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-compute', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-compute-ironic', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-compute-xen', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-conductor', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-novncproxy', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-scheduler', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-serialproxy', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'nova-volume', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'python3-nova', 'pkgver': '3:25.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-api', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-api-metadata', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-api-os-compute', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-api-os-volume', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-cells', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-common', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-compute', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-compute-ironic', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-compute-kvm', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-compute-libvirt', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-compute-lxc', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-compute-qemu', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-compute-vmware', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-compute-xen', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-conductor', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-novncproxy', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-scheduler', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-serialproxy', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-spiceproxy', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'nova-volume', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'python3-nova', 'pkgver': '3:26.1.0-0ubuntu2.2'},
    {'osver': '23.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-api', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-api-metadata', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-cells', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-common', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-compute', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-compute-ironic', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-compute-xen', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-conductor', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-novncproxy', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-scheduler', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-serialproxy', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'nova-volume', 'pkgver': '3:27.0.0-0ubuntu1.2'},
    {'osver': '23.04', 'pkgname': 'python3-nova', 'pkgver': '3:27.0.0-0ubuntu1.2'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nova-ajax-console-proxy / nova-api / nova-api-metadata / etc');
}
