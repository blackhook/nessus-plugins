##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5459-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161789);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2020-14342",
    "CVE-2021-20208",
    "CVE-2022-27239",
    "CVE-2022-29869"
  );
  script_xref(name:"USN", value:"5459-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : cifs-utils vulnerabilities (USN-5459-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has a package installed that is affected by multiple
vulnerabilities as referenced in the USN-5459-1 advisory.

  - It was found that cifs-utils' mount.cifs was invoking a shell when requesting the Samba password, which
    could be used to inject arbitrary commands. An attacker able to invoke mount.cifs with special permission,
    such as via sudo rules, could use this flaw to escalate their privileges. (CVE-2020-14342)

  - A flaw was found in cifs-utils in versions before 6.13. A user when mounting a krb5 CIFS file system from
    within a container can use Kerberos credentials of the host. The highest threat from this vulnerability is
    to data confidentiality and integrity. (CVE-2021-20208)

  - In cifs-utils through 6.14, a stack-based buffer overflow when parsing the mount.cifs ip= command-line
    argument could lead to local attackers gaining root privileges. (CVE-2022-27239)

  - cifs-utils through 6.14, with verbose logging, can cause an information leak when a file contains = (equal
    sign) characters but is not a valid credentials file. (CVE-2022-29869)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5459-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected cifs-utils package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27239");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cifs-utils");
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
    {'osver': '18.04', 'pkgname': 'cifs-utils', 'pkgver': '2:6.8-1ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'cifs-utils', 'pkgver': '2:6.9-1ubuntu0.2'},
    {'osver': '21.10', 'pkgname': 'cifs-utils', 'pkgver': '2:6.11-3.1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'cifs-utils', 'pkgver': '2:6.14-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cifs-utils');
}
