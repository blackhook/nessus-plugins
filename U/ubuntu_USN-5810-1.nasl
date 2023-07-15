#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5810-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170111);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-23521", "CVE-2022-41903");
  script_xref(name:"USN", value:"5810-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Git vulnerabilities (USN-5810-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5810-1 advisory.

  - Git is distributed revision control system. `git log` can display commits in an arbitrary format using its
    `--format` specifiers. This functionality is also exposed to `git archive` via the `export-subst`
    gitattribute. When processing the padding operators, there is a integer overflow in
    `pretty.c::format_and_pad_commit()` where a `size_t` is stored improperly as an `int`, and then added as
    an offset to a `memcpy()`. This overflow can be triggered directly by a user running a command which
    invokes the commit formatting machinery (e.g., `git log --format=...`). It may also be triggered
    indirectly through git archive via the export-subst mechanism, which expands format specifiers inside of
    files within the repository during a git archive. This integer overflow can result in arbitrary heap
    writes, which may result in arbitrary code execution. The problem has been patched in the versions
    published on 2023-01-17, going back to v2.30.7. Users are advised to upgrade. Users who are unable to
    upgrade should disable `git archive` in untrusted repositories. If you expose git archive via `git
    daemon`, disable it by running `git config --global daemon.uploadArch false`. (CVE-2022-41903)

  - Git is distributed revision control system. gitattributes are a mechanism to allow defining attributes for
    paths. These attributes can be defined by adding a `.gitattributes` file to the repository, which contains
    a set of file patterns and the attributes that should be set for paths matching this pattern. When parsing
    gitattributes, multiple integer overflows can occur when there is a huge number of path patterns, a huge
    number of attributes for a single pattern, or when the declared attribute names are huge. These overflows
    can be triggered via a crafted `.gitattributes` file that may be part of the commit history. Git silently
    splits lines longer than 2KB when parsing gitattributes from a file, but not when parsing them from the
    index. Consequentially, the failure mode depends on whether the file exists in the working tree, the index
    or both. This integer overflow can result in arbitrary heap reads and writes, which may result in remote
    code execution. The problem has been patched in the versions published on 2023-01-17, going back to
    v2.30.7. Users are advised to upgrade. There are no known workarounds for this issue. (CVE-2022-23521)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5810-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'git', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'git-all', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'git-el', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'git-email', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'git-gui', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'git-man', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'git-svn', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'gitk', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '18.04', 'pkgname': 'gitweb', 'pkgver': '1:2.17.1-1ubuntu0.14'},
    {'osver': '20.04', 'pkgname': 'git', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'git-all', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'git-el', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'git-email', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'git-gui', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'git-man', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'git-svn', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'gitk', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'gitweb', 'pkgver': '1:2.25.1-1ubuntu3.7'},
    {'osver': '22.04', 'pkgname': 'git', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'git-all', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'git-email', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'git-gui', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'git-man', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'git-svn', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'gitk', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'gitweb', 'pkgver': '1:2.34.1-1ubuntu1.6'},
    {'osver': '22.10', 'pkgname': 'git', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'git-all', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'git-cvs', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'git-email', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'git-gui', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'git-man', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'git-svn', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'gitk', 'pkgver': '1:2.37.2-1ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'gitweb', 'pkgver': '1:2.37.2-1ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git / git-all / git-cvs / git-daemon-run / git-daemon-sysvinit / etc');
}
