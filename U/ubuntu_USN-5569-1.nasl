##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5569-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164157);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2022-30698", "CVE-2022-30699");
  script_xref(name:"USN", value:"5569-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : Unbound vulnerabilities (USN-5569-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5569-1 advisory.

  - NLnet Labs Unbound, up to and including version 1.16.1 is vulnerable to a novel type of the ghost domain
    names attack. The vulnerability works by targeting an Unbound instance. Unbound is queried for a
    subdomain of a rogue domain name. The rogue nameserver returns delegation information for the subdomain
    that updates Unbound's delegation cache. This action can be repeated before expiry of the delegation
    information by querying Unbound for a second level subdomain which the rogue nameserver provides new
    delegation information. Since Unbound is a child-centric resolver, the ever-updating child delegation
    information can keep a rogue domain name resolvable long after revocation. From version 1.16.2 on, Unbound
    checks the validity of parent delegation records before using cached delegation information.
    (CVE-2022-30698)

  - NLnet Labs Unbound, up to and including version 1.16.1, is vulnerable to a novel type of the ghost domain
    names attack. The vulnerability works by targeting an Unbound instance. Unbound is queried for a rogue
    domain name when the cached delegation information is about to expire. The rogue nameserver delays the
    response so that the cached delegation information is expired. Upon receiving the delayed answer
    containing the delegation information, Unbound overwrites the now expired entries. This action can be
    repeated when the delegation information is about to expire making the rogue delegation information ever-
    updating. From version 1.16.2 on, Unbound stores the start time for a query and uses that to decide if the
    cached delegation information can be overwritten. (CVE-2022-30699)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5569-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunbound-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunbound2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunbound8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:unbound-anchor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:unbound-host");
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
    {'osver': '18.04', 'pkgname': 'libunbound-dev', 'pkgver': '1.6.7-1ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'libunbound2', 'pkgver': '1.6.7-1ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'python-unbound', 'pkgver': '1.6.7-1ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'python3-unbound', 'pkgver': '1.6.7-1ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'unbound', 'pkgver': '1.6.7-1ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'unbound-anchor', 'pkgver': '1.6.7-1ubuntu2.5'},
    {'osver': '18.04', 'pkgname': 'unbound-host', 'pkgver': '1.6.7-1ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'libunbound-dev', 'pkgver': '1.9.4-2ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libunbound8', 'pkgver': '1.9.4-2ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'python-unbound', 'pkgver': '1.9.4-2ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'python3-unbound', 'pkgver': '1.9.4-2ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'unbound', 'pkgver': '1.9.4-2ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'unbound-anchor', 'pkgver': '1.9.4-2ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'unbound-host', 'pkgver': '1.9.4-2ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'libunbound-dev', 'pkgver': '1.13.1-1ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libunbound8', 'pkgver': '1.13.1-1ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'python3-unbound', 'pkgver': '1.13.1-1ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'unbound', 'pkgver': '1.13.1-1ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'unbound-anchor', 'pkgver': '1.13.1-1ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'unbound-host', 'pkgver': '1.13.1-1ubuntu5.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libunbound-dev / libunbound2 / libunbound8 / python-unbound / etc');
}
