#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5076-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153243);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-40330");
  script_xref(name:"USN", value:"5076-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : Git vulnerability (USN-5076-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-5076-1 advisory.

  - git_connect_git in connect.c in Git before 2.30.1 allows a repository path to contain a newline character,
    which may result in unexpected cross-protocol requests, as demonstrated by the
    git://localhost:1234/%0d%0a%0d%0aGET%20/%20HTTP/1.1 substring. (CVE-2021-40330)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5076-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40330");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-daemon-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-daemon-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gitweb");
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
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '16.04', 'pkgname': 'git', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-all', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-arch', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-core', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-el', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-email', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-gui', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-man', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'git-svn', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'gitk', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '16.04', 'pkgname': 'gitweb', 'pkgver': '1:2.7.4-0ubuntu1.10+esm1'},
    {'osver': '18.04', 'pkgname': 'git', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'git-all', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'git-el', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'git-email', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'git-gui', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'git-man', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'git-svn', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'gitk', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '18.04', 'pkgname': 'gitweb', 'pkgver': '1:2.17.1-1ubuntu0.9'},
    {'osver': '20.04', 'pkgname': 'git', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'git-all', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'git-el', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'git-email', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'git-gui', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'git-man', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'git-svn', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'gitk', 'pkgver': '1:2.25.1-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'gitweb', 'pkgver': '1:2.25.1-1ubuntu3.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git / git-all / git-arch / git-core / git-cvs / git-daemon-run / etc');
}
