#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5686-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168011);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-39253", "CVE-2022-39260");
  script_xref(name:"USN", value:"5686-3");

  script_name(english:"Ubuntu 22.10 : Git vulnerabilities (USN-5686-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
USN-5686-3 advisory.

  - Git is an open source, scalable, distributed revision control system. Versions prior to 2.30.6, 2.31.5,
    2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 are subject to exposure of sensitive information to a
    malicious actor. When performing a local clone (where the source and target of the clone are on the same
    volume), Git copies the contents of the source's `$GIT_DIR/objects` directory into the destination by
    either creating hardlinks to the source contents, or copying them (if hardlinks are disabled via `--no-
    hardlinks`). A malicious actor could convince a victim to clone a repository with a symbolic link pointing
    at sensitive information on the victim's machine. This can be done either by having the victim clone a
    malicious repository on the same machine, or having them clone a malicious repository embedded as a bare
    repository via a submodule from any source, provided they clone with the `--recurse-submodules` option.
    Git does not create symbolic links in the `$GIT_DIR/objects` directory. The problem has been patched in
    the versions published on 2022-10-18, and backported to v2.30.x. Potential workarounds: Avoid cloning
    untrusted repositories using the `--local` optimization when on a shared machine, either by passing the
    `--no-local` option to `git clone` or cloning from a URL that uses the `file://` scheme. Alternatively,
    avoid cloning repositories from untrusted sources with `--recurse-submodules` or run `git config --global
    protocol.file.allow user`. (CVE-2022-39253)

  - Git is an open source, scalable, distributed revision control system. `git shell` is a restricted login
    shell that can be used to implement Git's push/pull functionality via SSH. In versions prior to 2.30.6,
    2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4, the function that splits the command arguments
    into an array improperly uses an `int` to represent the number of entries in the array, allowing a
    malicious actor to intentionally overflow the return value, leading to arbitrary heap writes. Because the
    resulting array is then passed to `execv()`, it is possible to leverage this attack to gain remote code
    execution on a victim machine. Note that a victim must first allow access to `git shell` as a login shell
    in order to be vulnerable to this attack. This problem is patched in versions 2.30.6, 2.31.5, 2.32.4,
    2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 and users are advised to upgrade to the latest version.
    Disabling `git shell` access via remote logins is a viable short-term workaround. (CVE-2022-39260)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5686-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39260");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-daemon-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-daemon-sysvinit");
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
if (! ('22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.10', 'pkgname': 'git', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'git-all', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'git-cvs', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'git-email', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'git-gui', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'git-man', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'git-svn', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'gitk', 'pkgver': '1:2.37.2-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'gitweb', 'pkgver': '1:2.37.2-1ubuntu1.1'}
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
