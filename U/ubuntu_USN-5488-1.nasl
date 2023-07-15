##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5488-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162424);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-2068");
  script_xref(name:"USN", value:"5488-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : OpenSSL vulnerability (USN-5488-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by a
vulnerability as referenced in the USN-5488-1 advisory.

  - In addition to the c_rehash shell command injection identified in CVE-2022-1292, further circumstances
    where the c_rehash script does not properly sanitise shell metacharacters to prevent command injection
    were found by code review. When the CVE-2022-1292 was fixed it was not discovered that there are other
    places in the script where the file names of certificates being hashed were possibly passed to a command
    executed through the shell. This script is distributed by some operating systems in a manner where it is
    automatically executed. On such operating systems, an attacker could execute arbitrary commands with the
    privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the
    OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.4 (Affected 3.0.0,3.0.1,3.0.2,3.0.3). Fixed in
    OpenSSL 1.1.1p (Affected 1.1.1-1.1.1o). Fixed in OpenSSL 1.0.2zf (Affected 1.0.2-1.0.2ze). (CVE-2022-2068)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5488-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl1.0");
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
    {'osver': '18.04', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1-1ubuntu2.1~18.04.19'},
    {'osver': '18.04', 'pkgname': 'libssl1.0-dev', 'pkgver': '1.0.2n-1ubuntu5.10'},
    {'osver': '18.04', 'pkgname': 'libssl1.0.0', 'pkgver': '1.0.2n-1ubuntu5.10'},
    {'osver': '18.04', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1-1ubuntu2.1~18.04.19'},
    {'osver': '18.04', 'pkgname': 'openssl', 'pkgver': '1.1.1-1ubuntu2.1~18.04.19'},
    {'osver': '18.04', 'pkgname': 'openssl1.0', 'pkgver': '1.0.2n-1ubuntu5.10'},
    {'osver': '20.04', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1f-1ubuntu2.15'},
    {'osver': '20.04', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1f-1ubuntu2.15'},
    {'osver': '20.04', 'pkgname': 'openssl', 'pkgver': '1.1.1f-1ubuntu2.15'},
    {'osver': '21.10', 'pkgname': 'libssl-dev', 'pkgver': '1.1.1l-1ubuntu1.5'},
    {'osver': '21.10', 'pkgname': 'libssl1.1', 'pkgver': '1.1.1l-1ubuntu1.5'},
    {'osver': '21.10', 'pkgname': 'openssl', 'pkgver': '1.1.1l-1ubuntu1.5'},
    {'osver': '22.04', 'pkgname': 'libssl-dev', 'pkgver': '3.0.2-0ubuntu1.5'},
    {'osver': '22.04', 'pkgname': 'libssl3', 'pkgver': '3.0.2-0ubuntu1.5'},
    {'osver': '22.04', 'pkgname': 'openssl', 'pkgver': '3.0.2-0ubuntu1.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libssl-dev / libssl1.0-dev / libssl1.0.0 / libssl1.1 / libssl3 / etc');
}
