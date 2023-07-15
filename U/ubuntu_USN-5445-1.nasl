##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5445-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161576);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2018-11782", "CVE-2019-0203", "CVE-2020-17525");
  script_xref(name:"USN", value:"5445-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Subversion vulnerabilities (USN-5445-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5445-1 advisory.

  - In Apache Subversion versions up to and including 1.9.10, 1.10.4, 1.12.0, Subversion's svnserve server
    process may exit when a well-formed read-only request produces a particular answer. This can lead to
    disruption for users of the server. (CVE-2018-11782)

  - In Apache Subversion versions up to and including 1.9.10, 1.10.4, 1.12.0, Subversion's svnserve server
    process may exit when a client sends certain sequences of protocol commands. This can lead to disruption
    for users of the server. (CVE-2019-0203)

  - Subversion's mod_authz_svn module will crash if the server is using in-repository authz rules with the
    AuthzSVNReposRelativeAccessFile option and a client sends a request for a non-existing repository URL.
    This can lead to disruption for users of the service. This issue was fixed in mod_dav_svn+mod_authz_svn
    servers 1.14.1 and mod_dav_svn+mod_authz_svn servers 1.10.7 (CVE-2020-17525)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5445-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0203");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-17525");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:subversion-tools");
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
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libapache2-mod-svn', 'pkgver': '1.9.7-4ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libsvn-dev', 'pkgver': '1.9.7-4ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libsvn-java', 'pkgver': '1.9.7-4ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libsvn-perl', 'pkgver': '1.9.7-4ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'libsvn1', 'pkgver': '1.9.7-4ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'python-subversion', 'pkgver': '1.9.7-4ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'ruby-svn', 'pkgver': '1.9.7-4ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'subversion', 'pkgver': '1.9.7-4ubuntu1.1'},
    {'osver': '18.04', 'pkgname': 'subversion-tools', 'pkgver': '1.9.7-4ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-svn', 'pkgver': '1.13.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsvn-dev', 'pkgver': '1.13.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsvn-java', 'pkgver': '1.13.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsvn-perl', 'pkgver': '1.13.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsvn1', 'pkgver': '1.13.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'python-subversion', 'pkgver': '1.13.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'ruby-svn', 'pkgver': '1.13.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'subversion', 'pkgver': '1.13.0-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'subversion-tools', 'pkgver': '1.13.0-3ubuntu0.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-svn / libsvn-dev / libsvn-java / libsvn-perl / etc');
}
