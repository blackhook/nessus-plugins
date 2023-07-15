#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6068-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175567);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/13");

  script_cve_id("CVE-2023-1668");
  script_xref(name:"USN", value:"6068-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Open vSwitch vulnerability (USN-6068-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-6068-1 advisory.

  - A flaw was found in openvswitch (OVS). When processing an IP packet with protocol 0, OVS will install the
    datapath flow without the action modifying the IP header. This issue results (for both kernel and
    userspace datapath) in installing a datapath flow matching all IP protocols (nw_proto is wildcarded) for
    this flow, but with an incorrect action, possibly causing incorrect handling of other IP packets with a !=
    0 IP protocol that matches this dp flow. (CVE-2023-1668)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6068-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1668");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-switch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-switch-dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-testcontroller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvswitch-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovn-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovn-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovn-controller-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ovn-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-openvswitch");
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
if (! preg(pattern:"^(18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'openvswitch-common', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'openvswitch-pki', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'openvswitch-switch', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'openvswitch-switch-dpdk', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'openvswitch-test', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'openvswitch-testcontroller', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'openvswitch-vtep', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'ovn-central', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'ovn-common', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'ovn-controller-vtep', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'ovn-host', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'python-openvswitch', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'python3-openvswitch', 'pkgver': '2.9.8-0ubuntu0.18.04.5'},
    {'osver': '20.04', 'pkgname': 'openvswitch-common', 'pkgver': '2.13.8-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'openvswitch-pki', 'pkgver': '2.13.8-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'openvswitch-source', 'pkgver': '2.13.8-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'openvswitch-switch', 'pkgver': '2.13.8-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'openvswitch-switch-dpdk', 'pkgver': '2.13.8-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'openvswitch-test', 'pkgver': '2.13.8-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'openvswitch-testcontroller', 'pkgver': '2.13.8-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'openvswitch-vtep', 'pkgver': '2.13.8-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'python3-openvswitch', 'pkgver': '2.13.8-0ubuntu1.2'},
    {'osver': '22.04', 'pkgname': 'openvswitch-common', 'pkgver': '2.17.5-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'openvswitch-ipsec', 'pkgver': '2.17.5-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'openvswitch-pki', 'pkgver': '2.17.5-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'openvswitch-source', 'pkgver': '2.17.5-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'openvswitch-switch', 'pkgver': '2.17.5-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'openvswitch-switch-dpdk', 'pkgver': '2.17.5-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'openvswitch-test', 'pkgver': '2.17.5-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'openvswitch-testcontroller', 'pkgver': '2.17.5-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'openvswitch-vtep', 'pkgver': '2.17.5-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'python3-openvswitch', 'pkgver': '2.17.5-0ubuntu0.22.04.2'},
    {'osver': '22.10', 'pkgname': 'openvswitch-common', 'pkgver': '3.0.3-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'openvswitch-ipsec', 'pkgver': '3.0.3-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'openvswitch-pki', 'pkgver': '3.0.3-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'openvswitch-source', 'pkgver': '3.0.3-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'openvswitch-switch', 'pkgver': '3.0.3-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'openvswitch-switch-dpdk', 'pkgver': '3.0.3-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'openvswitch-test', 'pkgver': '3.0.3-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'openvswitch-testcontroller', 'pkgver': '3.0.3-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'openvswitch-vtep', 'pkgver': '3.0.3-0ubuntu0.22.10.3'},
    {'osver': '22.10', 'pkgname': 'python3-openvswitch', 'pkgver': '3.0.3-0ubuntu0.22.10.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openvswitch-common / openvswitch-ipsec / openvswitch-pki / etc');
}
