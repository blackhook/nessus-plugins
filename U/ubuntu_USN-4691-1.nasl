##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4691-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144943);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2015-8011", "CVE-2020-27827");
  script_bugtraq_id(77114);
  script_xref(name:"USN", value:"4691-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : Open vSwitch vulnerabilities (USN-4691-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4691-1 advisory.

  - Buffer overflow in the lldp_decode function in daemon/protocols/lldp.c in lldpd before 0.8.0 allows remote
    attackers to cause a denial of service (daemon crash) and possibly execute arbitrary code via vectors
    involving large management addresses and TLV boundaries. (CVE-2015-8011)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4691-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8011");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'openvswitch-common', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-ipsec', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-pki', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-switch', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-switch-dpdk', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-test', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-testcontroller', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'openvswitch-vtep', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'ovn-central', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'ovn-common', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'ovn-host', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '16.04', 'pkgname': 'python-openvswitch', 'pkgver': '2.5.9-0ubuntu0.16.04.2'},
    {'osver': '18.04', 'pkgname': 'openvswitch-common', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'openvswitch-pki', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'openvswitch-switch', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'openvswitch-switch-dpdk', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'openvswitch-test', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'openvswitch-testcontroller', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'openvswitch-vtep', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ovn-central', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ovn-common', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ovn-controller-vtep', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ovn-host', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python-openvswitch', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3-openvswitch', 'pkgver': '2.9.7-0ubuntu0.18.04.2'},
    {'osver': '20.04', 'pkgname': 'openvswitch-common', 'pkgver': '2.13.1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'openvswitch-pki', 'pkgver': '2.13.1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'openvswitch-source', 'pkgver': '2.13.1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'openvswitch-switch', 'pkgver': '2.13.1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'openvswitch-switch-dpdk', 'pkgver': '2.13.1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'openvswitch-test', 'pkgver': '2.13.1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'openvswitch-testcontroller', 'pkgver': '2.13.1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'openvswitch-vtep', 'pkgver': '2.13.1-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'python3-openvswitch', 'pkgver': '2.13.1-0ubuntu0.20.04.3'},
    {'osver': '20.10', 'pkgname': 'openvswitch-common', 'pkgver': '2.13.1-0ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'openvswitch-pki', 'pkgver': '2.13.1-0ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'openvswitch-source', 'pkgver': '2.13.1-0ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'openvswitch-switch', 'pkgver': '2.13.1-0ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'openvswitch-switch-dpdk', 'pkgver': '2.13.1-0ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'openvswitch-test', 'pkgver': '2.13.1-0ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'openvswitch-testcontroller', 'pkgver': '2.13.1-0ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'openvswitch-vtep', 'pkgver': '2.13.1-0ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'python3-openvswitch', 'pkgver': '2.13.1-0ubuntu1.2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openvswitch-common / openvswitch-ipsec / openvswitch-pki / etc');
}