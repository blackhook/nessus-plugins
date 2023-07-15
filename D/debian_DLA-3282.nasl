#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3282. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170680);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2022-23521", "CVE-2022-41903");

  script_name(english:"Debian DLA-3282-1 : git - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3282 advisory.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1029114");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/git");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23521");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41903");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/git");
  script_set_attribute(attribute:"solution", value:
"Upgrade the git packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-daemon-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-daemon-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'git', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-all', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-cvs', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-daemon-run', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-daemon-sysvinit', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-doc', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-el', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-email', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-gui', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-man', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-mediawiki', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'git-svn', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'gitk', 'reference': '1:2.20.1-2+deb10u7'},
    {'release': '10.0', 'prefix': 'gitweb', 'reference': '1:2.20.1-2+deb10u7'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git / git-all / git-cvs / git-daemon-run / git-daemon-sysvinit / etc');
}
