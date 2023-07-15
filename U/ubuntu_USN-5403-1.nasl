##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5403-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160538);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2021-36690");
  script_xref(name:"USN", value:"5403-1");

  script_name(english:"Ubuntu 18.04 LTS : SQLite vulnerability (USN-5403-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-5403-1 advisory.

  - ** DISPUTED ** A segmentation fault can occur in the sqlite3.exe command-line component of SQLite 3.36.0
    via the idxGetTableInfo function when there is a crafted SQL query. NOTE: the vendor disputes the
    relevance of this report because a sqlite3.exe user already has full privileges (e.g., is intentionally
    allowed to execute commands). This report does NOT imply any problem in the SQLite library.
    (CVE-2021-36690)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5403-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36690");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sqlite3");
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
    {'osver': '18.04', 'pkgname': 'lemon', 'pkgver': '3.22.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'libsqlite3-0', 'pkgver': '3.22.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'libsqlite3-dev', 'pkgver': '3.22.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'libsqlite3-tcl', 'pkgver': '3.22.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'sqlite3', 'pkgver': '3.22.0-1ubuntu0.5'},
    {'osver': '20.04', 'pkgname': 'lemon', 'pkgver': '3.31.1-4ubuntu0.3'},
    {'osver': '20.04', 'pkgname': 'libsqlite3-0', 'pkgver': '3.31.1-4ubuntu0.3'},
    {'osver': '20.04', 'pkgname': 'libsqlite3-dev', 'pkgver': '3.31.1-4ubuntu0.3'},
    {'osver': '20.04', 'pkgname': 'libsqlite3-tcl', 'pkgver': '3.31.1-4ubuntu0.3'},
    {'osver': '20.04', 'pkgname': 'sqlite3', 'pkgver': '3.31.1-4ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'lemon', 'pkgver': '3.35.5-1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsqlite3-0', 'pkgver': '3.35.5-1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsqlite3-dev', 'pkgver': '3.35.5-1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsqlite3-tcl', 'pkgver': '3.35.5-1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'sqlite3', 'pkgver': '3.35.5-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lemon / libsqlite3-0 / libsqlite3-dev / libsqlite3-tcl / sqlite3');
}
