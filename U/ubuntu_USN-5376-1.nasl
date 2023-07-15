#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5376-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159687);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-24765");
  script_xref(name:"USN", value:"5376-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : Git vulnerability (USN-5376-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-5376-1 advisory.

  - Git for Windows is a fork of Git containing Windows-specific patches. This vulnerability affects users
    working on multi-user machines, where untrusted parties have write access to the same hard disk. Those
    untrusted parties could create the folder `C:\.git`, which would be picked up by Git operations run
    supposedly outside a repository while searching for a Git directory. Git would then respect any config in
    said Git directory. Git Bash users who set `GIT_PS1_SHOWDIRTYSTATE` are vulnerable as well. Users who
    installed posh-gitare vulnerable simply by starting a PowerShell. Users of IDEs such as Visual Studio are
    vulnerable: simply creating a new project would already read and respect the config specified in
    `C:\.git\config`. Users of the Microsoft fork of Git are vulnerable simply by starting a Git Bash. The
    problem has been patched in Git for Windows v2.35.2. Users unable to upgrade may create the folder `.git`
    on all drives where Git commands are run, and remove read/write access from those folders as a workaround.
    Alternatively, define or extend `GIT_CEILING_DIRECTORIES` to cover the _parent_ directory of the user
    profile, e.g. `C:\Users` if the user profile is located in `C:\Users\my-user-name`. (CVE-2022-24765)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5376-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24765");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-all");
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
    {'osver': '18.04', 'pkgname': 'git', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'git-all', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'git-el', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'git-email', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'git-gui', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'git-man', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'git-svn', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'gitk', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '18.04', 'pkgname': 'gitweb', 'pkgver': '1:2.17.1-1ubuntu0.10'},
    {'osver': '20.04', 'pkgname': 'git', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'git-all', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'git-el', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'git-email', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'git-gui', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'git-man', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'git-svn', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'gitk', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'gitweb', 'pkgver': '1:2.25.1-1ubuntu3.3'},
    {'osver': '21.10', 'pkgname': 'git', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'git-all', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'git-cvs', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'git-email', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'git-gui', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'git-man', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'git-svn', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'gitk', 'pkgver': '1:2.32.0-1ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'gitweb', 'pkgver': '1:2.32.0-1ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git / git-all / git-cvs / git-daemon-run / git-daemon-sysvinit / etc');
}
