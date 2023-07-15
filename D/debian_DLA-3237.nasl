#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3237. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168639);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/12");

  script_cve_id("CVE-2021-37701", "CVE-2021-37712");

  script_name(english:"Debian DLA-3237-1 : node-tar - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3237 advisory.

  - The npm package tar (aka node-tar) before versions 4.4.16, 5.0.8, and 6.1.7 has an arbitrary file
    creation/overwrite and arbitrary code execution vulnerability. node-tar aims to guarantee that any file
    whose location would be modified by a symbolic link is not extracted. This is, in part, achieved by
    ensuring that extracted directories are not symlinks. Additionally, in order to prevent unnecessary stat
    calls to determine whether a given path is a directory, paths are cached when directories are created.
    This logic was insufficient when extracting tar files that contained both a directory and a symlink with
    the same name as the directory, where the symlink and directory names in the archive entry used
    backslashes as a path separator on posix systems. The cache checking logic used both `\` and `/`
    characters as path separators, however `\` is a valid filename character on posix systems. By first
    creating a directory, and then replacing that directory with a symlink, it was thus possible to bypass
    node-tar symlink checks on directories, essentially allowing an untrusted tar file to symlink into an
    arbitrary location and subsequently extracting arbitrary files into that location, thus allowing arbitrary
    file creation and overwrite. Additionally, a similar confusion could arise on case-insensitive
    filesystems. If a tar archive contained a directory at `FOO`, followed by a symbolic link named `foo`,
    then on case-insensitive file systems, the creation of the symbolic link would remove the directory from
    the filesystem, but _not_ from the internal directory cache, as it would not be treated as a cache hit. A
    subsequent file entry within the `FOO` directory would then be placed in the target of the symbolic link,
    thinking that the directory had already been created. These issues were addressed in releases 4.4.16,
    5.0.8 and 6.1.7. The v3 branch of node-tar has been deprecated and did not receive patches for these
    issues. If you are still using a v3 release we recommend you update to a more recent version of node-tar.
    If this is not possible, a workaround is available in the referenced GHSA-9r2w-394v-53qc. (CVE-2021-37701)

  - The npm package tar (aka node-tar) before versions 4.4.18, 5.0.10, and 6.1.9 has an arbitrary file
    creation/overwrite and arbitrary code execution vulnerability. node-tar aims to guarantee that any file
    whose location would be modified by a symbolic link is not extracted. This is, in part, achieved by
    ensuring that extracted directories are not symlinks. Additionally, in order to prevent unnecessary stat
    calls to determine whether a given path is a directory, paths are cached when directories are created.
    This logic was insufficient when extracting tar files that contained both a directory and a symlink with
    names containing unicode values that normalized to the same value. Additionally, on Windows systems, long
    path portions would resolve to the same file system entities as their 8.3 short path counterparts. A
    specially crafted tar archive could thus include a directory with one form of the path, followed by a
    symbolic link with a different string that resolves to the same file system entity, followed by a file
    using the first form. By first creating a directory, and then replacing that directory with a symlink that
    had a different apparent name that resolved to the same entry in the filesystem, it was thus possible to
    bypass node-tar symlink checks on directories, essentially allowing an untrusted tar file to symlink into
    an arbitrary location and subsequently extracting arbitrary files into that location, thus allowing
    arbitrary file creation and overwrite. These issues were addressed in releases 4.4.18, 5.0.10 and 6.1.9.
    The v3 branch of node-tar has been deprecated and did not receive patches for these issues. If you are
    still using a v3 release we recommend you update to a more recent version of node-tar. If this is not
    possible, a workaround is available in the referenced GHSA-qq89-hq3f-393p. (CVE-2021-37712)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=993981");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/node-tar");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3237");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37701");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37712");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/node-tar");
  script_set_attribute(attribute:"solution", value:
"Upgrade the node-tar packages.

For Debian 10 buster, these problems have been fixed in version 4.4.6+ds1-3+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-tar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'node-tar', 'reference': '4.4.6+ds1-3+deb10u2'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'node-tar');
}
