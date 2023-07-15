#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5387-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160188);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-23451", "CVE-2022-23452");
  script_xref(name:"USN", value:"5387-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : Barbican vulnerabilities (USN-5387-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5387-1 advisory.

  - An authorization flaw was found in openstack-barbican. The default policy rules for the secret metadata
    API allowed any authenticated user to add, modify, or delete metadata from any secret regardless of
    ownership. This flaw allows an attacker on the network to modify or delete protected data, causing a
    denial of service by consuming protected resources. (CVE-2022-23451)

  - An authorization flaw was found in openstack-barbican, where anyone with an admin role could add secrets
    to a different project container. This flaw allows an attacker on the network to consume protected
    resources and cause a denial of service. (CVE-2022-23452)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5387-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23451");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:barbican-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:barbican-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:barbican-keystone-listener");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:barbican-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-barbican");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-barbican");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'barbican-api', 'pkgver': '1:6.0.1-0ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'barbican-common', 'pkgver': '1:6.0.1-0ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'barbican-keystone-listener', 'pkgver': '1:6.0.1-0ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'barbican-worker', 'pkgver': '1:6.0.1-0ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'python-barbican', 'pkgver': '1:6.0.1-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'barbican-api', 'pkgver': '1:10.1.0-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'barbican-common', 'pkgver': '1:10.1.0-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'barbican-keystone-listener', 'pkgver': '1:10.1.0-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'barbican-worker', 'pkgver': '1:10.1.0-0ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'python3-barbican', 'pkgver': '1:10.1.0-0ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'barbican-api', 'pkgver': '2:13.0.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'barbican-common', 'pkgver': '2:13.0.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'barbican-keystone-listener', 'pkgver': '2:13.0.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'barbican-worker', 'pkgver': '2:13.0.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'python3-barbican', 'pkgver': '2:13.0.0-0ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'barbican-api / barbican-common / barbican-keystone-listener / etc');
}
