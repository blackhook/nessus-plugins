#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5713-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166941);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-42919");
  script_xref(name:"USN", value:"5713-1");
  script_xref(name:"IAVA", value:"2022-A-0467-S");
  script_xref(name:"IAVA", value:"2023-A-0061-S");

  script_name(english:"Ubuntu 22.04 LTS / 22.10 : Python vulnerability (USN-5713-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 22.10 host has packages installed that are affected by a vulnerability as referenced in
the USN-5713-1 advisory.

  - Python 3.9.x before 3.9.16 and 3.10.x before 3.10.9 on Linux allows local privilege escalation in a non-
    default configuration. The Python multiprocessing library, when used with the forkserver start method on
    Linux, allows pickles to be deserialized from any user in the same machine local network namespace, which
    in many system configurations means any user on the same machine. Pickles can execute arbitrary code.
    Thus, this allows for local user privilege escalation to the user that any forkserver process is running
    as. Setting multiprocessing.util.abstract_sockets_supported to False is a workaround. The forkserver start
    method for multiprocessing is not the default start method. This issue is Linux specific because only
    Linux supports abstract namespace sockets. CPython before 3.9 does not make use of Linux abstract
    namespace sockets by default. Support for users manually specifying an abstract namespace socket was added
    as a bugfix in 3.7.8 and 3.8.3, but users would need to make specific uncommon API calls in order to do
    that in CPython before 3.9. (CVE-2022-42919)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5713-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-nopie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-venv");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'idle-python3.10', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpython3.10', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpython3.10-dev', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpython3.10-minimal', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpython3.10-stdlib', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'libpython3.10-testsuite', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'python3.10', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'python3.10-dev', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'python3.10-examples', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'python3.10-full', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'python3.10-minimal', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'python3.10-nopie', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'python3.10-venv', 'pkgver': '3.10.6-1~22.04.1'},
    {'osver': '22.10', 'pkgname': 'idle-python3.10', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libpython3.10', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libpython3.10-dev', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libpython3.10-minimal', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libpython3.10-stdlib', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libpython3.10-testsuite', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'python3.10', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'python3.10-dev', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'python3.10-examples', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'python3.10-full', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'python3.10-minimal', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'python3.10-nopie', 'pkgver': '3.10.7-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'python3.10-venv', 'pkgver': '3.10.7-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python3.10 / libpython3.10 / libpython3.10-dev / etc');
}
