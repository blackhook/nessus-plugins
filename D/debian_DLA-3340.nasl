#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3340. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171871);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/24");

  script_cve_id("CVE-2020-12278", "CVE-2020-12279", "CVE-2023-22742");

  script_name(english:"Debian DLA-3340-1 : libgit2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3340 advisory.

  - An issue was discovered in libgit2 before 0.28.4 and 0.9x before 0.99.0. path.c mishandles equivalent
    filenames that exist because of NTFS Alternate Data Streams. This may allow remote code execution when
    cloning a repository. This issue is similar to CVE-2019-1352. (CVE-2020-12278)

  - An issue was discovered in libgit2 before 0.28.4 and 0.9x before 0.99.0. checkout.c mishandles equivalent
    filenames that exist because of NTFS short names. This may allow remote code execution when cloning a
    repository. This issue is similar to CVE-2019-1353. (CVE-2020-12279)

  - libgit2 is a cross-platform, linkable library implementation of Git. When using an SSH remote with the
    optional libssh2 backend, libgit2 does not perform certificate checking by default. Prior versions of
    libgit2 require the caller to set the `certificate_check` field of libgit2's `git_remote_callbacks`
    structure - if a certificate check callback is not set, libgit2 does not perform any certificate checking.
    This means that by default - without configuring a certificate check callback, clients will not perform
    validation on the server SSH keys and may be subject to a man-in-the-middle attack. Users are encouraged
    to upgrade to v1.4.5 or v1.5.1. Users unable to upgrade should ensure that all relevant certificates are
    manually checked. (CVE-2023-22742)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1029368");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libgit2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3340");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12278");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12279");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-22742");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libgit2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libgit2 packages.

For Debian 10 buster, these problems have been fixed in version 0.27.7+dfsg.1-0.2+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12279");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgit2-27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgit2-dev");
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
    {'release': '10.0', 'prefix': 'libgit2-27', 'reference': '0.27.7+dfsg.1-0.2+deb10u1'},
    {'release': '10.0', 'prefix': 'libgit2-dev', 'reference': '0.27.7+dfsg.1-0.2+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libgit2-27 / libgit2-dev');
}
