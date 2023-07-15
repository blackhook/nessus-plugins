#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5119. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159709);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2021-28544", "CVE-2022-24070");

  script_name(english:"Debian DSA-5119-1 : subversion - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5119 advisory.

  - Apache Subversion SVN authz protected copyfrom paths regression Subversion servers reveal 'copyfrom' paths
    that should be hidden according to configured path-based authorization (authz) rules. When a node has been
    copied from a protected location, users with access to the copy can see the 'copyfrom' path of the
    original. This also reveals the fact that the node was copied. Only the 'copyfrom' path is revealed; not
    its contents. Both httpd and svnserve servers are vulnerable. (CVE-2021-28544)

  - Subversion's mod_dav_svn is vulnerable to memory corruption. While looking up path-based authorization
    rules, mod_dav_svn servers may attempt to use memory which has already been freed. Affected Subversion
    mod_dav_svn servers 1.10.0 through 1.14.1 (inclusive). Servers that do not use mod_dav_svn are not
    affected. (CVE-2022-24070)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/subversion");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5119");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28544");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24070");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/subversion");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/subversion");
  script_set_attribute(attribute:"solution", value:
"Upgrade the subversion packages.

For the stable distribution (bullseye), these problems have been fixed in version 1.14.1-3+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28544");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libapache2-mod-svn', 'reference': '1.10.4-1+deb10u3'},
    {'release': '10.0', 'prefix': 'libsvn-dev', 'reference': '1.10.4-1+deb10u3'},
    {'release': '10.0', 'prefix': 'libsvn-doc', 'reference': '1.10.4-1+deb10u3'},
    {'release': '10.0', 'prefix': 'libsvn-java', 'reference': '1.10.4-1+deb10u3'},
    {'release': '10.0', 'prefix': 'libsvn-perl', 'reference': '1.10.4-1+deb10u3'},
    {'release': '10.0', 'prefix': 'libsvn1', 'reference': '1.10.4-1+deb10u3'},
    {'release': '10.0', 'prefix': 'python-subversion', 'reference': '1.10.4-1+deb10u3'},
    {'release': '10.0', 'prefix': 'python3-subversion', 'reference': '1.10.4-1+deb10u3'},
    {'release': '10.0', 'prefix': 'ruby-svn', 'reference': '1.10.4-1+deb10u3'},
    {'release': '10.0', 'prefix': 'subversion', 'reference': '1.10.4-1+deb10u3'},
    {'release': '10.0', 'prefix': 'subversion-tools', 'reference': '1.10.4-1+deb10u3'},
    {'release': '11.0', 'prefix': 'libapache2-mod-svn', 'reference': '1.14.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'libsvn-dev', 'reference': '1.14.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'libsvn-doc', 'reference': '1.14.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'libsvn-java', 'reference': '1.14.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'libsvn-perl', 'reference': '1.14.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'libsvn1', 'reference': '1.14.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'python-subversion', 'reference': '1.14.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-subversion', 'reference': '1.14.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'ruby-svn', 'reference': '1.14.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'subversion', 'reference': '1.14.1-3+deb11u1'},
    {'release': '11.0', 'prefix': 'subversion-tools', 'reference': '1.14.1-3+deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-svn / libsvn-dev / libsvn-doc / libsvn-java / etc');
}
