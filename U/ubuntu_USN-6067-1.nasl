#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6067-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175565);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/13");

  script_cve_id(
    "CVE-2021-20267",
    "CVE-2021-38598",
    "CVE-2021-40085",
    "CVE-2021-40797",
    "CVE-2022-3277"
  );
  script_xref(name:"USN", value:"6067-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : OpenStack Neutron vulnerabilities (USN-6067-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6067-1 advisory.

  - A flaw was found in openstack-neutron's default Open vSwitch firewall rules. By sending carefully crafted
    packets, anyone in control of a server instance connected to the virtual switch can impersonate the IPv6
    addresses of other systems on the network, resulting in denial of service or in some cases possibly
    interception of traffic intended for other destinations. Only deployments using the Open vSwitch driver
    are affected. Source: OpenStack project. Versions before openstack-neutron 15.3.3, openstack-neutron
    16.3.1 and openstack-neutron 17.1.1 are affected. (CVE-2021-20267)

  - OpenStack Neutron before 16.4.1, 17.x before 17.1.3, and 18.0.0 allows hardware address impersonation when
    the linuxbridge driver with ebtables-nft is used on a Netfilter-based platform. By sending carefully
    crafted packets, anyone in control of a server instance connected to the virtual switch can impersonate
    the hardware addresses of other systems on the network, resulting in denial of service or in some cases
    possibly interception of traffic intended for other destinations. (CVE-2021-38598)

  - An issue was discovered in OpenStack Neutron before 16.4.1, 17.x before 17.2.1, and 18.x before 18.1.1.
    Authenticated attackers can reconfigure dnsmasq via a crafted extra_dhcp_opts value. (CVE-2021-40085)

  - An issue was discovered in the routes middleware in OpenStack Neutron before 16.4.1, 17.x before 17.2.1,
    and 18.x before 18.1.1. By making API requests involving nonexistent controllers, an authenticated user
    may cause the API worker to consume increasing amounts of memory, resulting in API performance degradation
    or denial of service. (CVE-2021-40797)

  - An uncontrolled resource consumption flaw was found in openstack-neutron. This flaw allows a remote
    authenticated user to query a list of security groups for an invalid project. This issue creates resources
    that are unconstrained by the user's quota. If a malicious user were to submit a significant number of
    requests, this could lead to a denial of service. (CVE-2022-3277)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6067-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38598");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-dhcp-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-l3-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-linuxbridge-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-macvtap-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-metadata-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-metering-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-openvswitch-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-ovn-metadata-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-linuxbridge-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-ml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-openvswitch-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-sriov-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-sriov-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-neutron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-neutron");
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
if (! preg(pattern:"^(18\.04|20\.04|22\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'neutron-common', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-dhcp-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-l3-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-linuxbridge-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-macvtap-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-metadata-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-metering-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-openvswitch-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-plugin-linuxbridge-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-plugin-ml2', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-plugin-openvswitch-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-plugin-sriov-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-server', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'neutron-sriov-agent', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '18.04', 'pkgname': 'python-neutron', 'pkgver': '2:12.1.1-0ubuntu8.1'},
    {'osver': '20.04', 'pkgname': 'neutron-common', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-dhcp-agent', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-l3-agent', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-linuxbridge-agent', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-macvtap-agent', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-metadata-agent', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-metering-agent', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-openvswitch-agent', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-ovn-metadata-agent', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-plugin-ml2', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-server', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'neutron-sriov-agent', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '20.04', 'pkgname': 'python3-neutron', 'pkgver': '2:16.4.2-0ubuntu6.2'},
    {'osver': '22.04', 'pkgname': 'neutron-common', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-dhcp-agent', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-l3-agent', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-linuxbridge-agent', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-macvtap-agent', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-metadata-agent', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-metering-agent', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-openvswitch-agent', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-ovn-metadata-agent', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-plugin-ml2', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-server', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'neutron-sriov-agent', 'pkgver': '2:20.3.0-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'python3-neutron', 'pkgver': '2:20.3.0-0ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'neutron-common / neutron-dhcp-agent / neutron-l3-agent / etc');
}
