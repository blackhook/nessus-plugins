#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5866-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171386);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/13");

  script_cve_id(
    "CVE-2015-9543",
    "CVE-2017-18191",
    "CVE-2020-17376",
    "CVE-2021-3654",
    "CVE-2022-37394"
  );
  script_xref(name:"USN", value:"5866-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS : Nova vulnerabilities (USN-5866-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5866-1 advisory.

  - An issue was discovered in OpenStack Nova before 18.2.4, 19.x before 19.1.0, and 20.x before 20.1.0. It
    can leak consoleauth tokens into log files. An attacker with read access to the service's logs may obtain
    tokens used for console access. All Nova setups using novncproxy are affected. This is related to
    NovaProxyRequestHandlerBase.new_websocket_client in console/websocketproxy.py. (CVE-2015-9543)

  - An issue was discovered in OpenStack Nova 15.x through 15.1.0 and 16.x through 16.1.1. By detaching and
    reattaching an encrypted volume, an attacker may access the underlying raw volume and corrupt the LUKS
    header, resulting in a denial of service attack on the compute host. (The same code error also results in
    data loss, but that is not a vulnerability because the user loses their own data.) All Nova setups
    supporting encrypted volumes are affected. (CVE-2017-18191)

  - An issue was discovered in Guest.migrate in virt/libvirt/guest.py in OpenStack Nova before 19.3.1, 20.x
    before 20.3.1, and 21.0.0. By performing a soft reboot of an instance that has previously undergone live
    migration, a user may gain access to destination host devices that share the same paths as host devices
    previously referenced by the virtual machine on the source host. This can include block devices that map
    to different Cinder volumes at the destination than at the source. Only deployments allowing host-based
    connections (for instance, root and ephemeral devices) are affected. (CVE-2020-17376)

  - A vulnerability was found in openstack-nova's console proxy, noVNC. By crafting a malicious URL, noVNC
    could be made to redirect to any desired URL. (CVE-2021-3654)

  - An issue was discovered in OpenStack Nova before 23.2.2, 24.x before 24.1.2, and 25.x before 25.0.2. By
    creating a neutron port with the direct vnic_type, creating an instance bound to that port, and then
    changing the vnic_type of the bound port to macvtap, an authenticated user may cause the compute service
    to fail to restart, resulting in a possible denial of service. Only Nova deployments configured with SR-
    IOV are affected. (CVE-2022-37394)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5866-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17376");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-ajax-console-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-os-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-os-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-cells");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-cert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-consoleauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-novncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-placement-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-serialproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-spiceproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-xvpvncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-nova");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-api', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-api-metadata', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-cells', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-cert', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-common', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-compute', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-compute-xen', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-conductor', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-console', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-consoleauth', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-network', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-novncproxy', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-scheduler', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-serialproxy', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-volume', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'nova-xvpvncproxy', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '16.04', 'pkgname': 'python-nova', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1'},
    {'osver': '18.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-api', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-api-metadata', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-cells', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-common', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-compute', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-compute-xen', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-conductor', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-console', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-consoleauth', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-network', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-novncproxy', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-placement-api', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-scheduler', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-serialproxy', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-volume', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'nova-xvpvncproxy', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '18.04', 'pkgname': 'python-nova', 'pkgver': '2:17.0.13-0ubuntu5.3'},
    {'osver': '20.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-api', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-api-metadata', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-cells', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-common', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-compute', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-compute-xen', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-conductor', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-novncproxy', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-scheduler', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-serialproxy', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'nova-volume', 'pkgver': '2:21.2.4-0ubuntu2.2'},
    {'osver': '20.04', 'pkgname': 'python3-nova', 'pkgver': '2:21.2.4-0ubuntu2.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nova-ajax-console-proxy / nova-api / nova-api-metadata / etc');
}
