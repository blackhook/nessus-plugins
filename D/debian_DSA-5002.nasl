#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5002. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154949);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/06");

  script_cve_id("CVE-2021-41103");

  script_name(english:"Debian DSA-5002-1 : containerd - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5002
advisory.

  - containerd is an open source container runtime with an emphasis on simplicity, robustness and portability.
    A bug was found in containerd where container root directories and some plugins had insufficiently
    restricted permissions, allowing otherwise unprivileged Linux users to traverse directory contents and
    execute programs. When containers included executable programs with extended permission bits (such as
    setuid), unprivileged Linux users could discover and execute those programs. When the UID of an
    unprivileged Linux user on the host collided with the file owner or group inside a container, the
    unprivileged Linux user on the host could discover, read, and modify those files. This vulnerability has
    been fixed in containerd 1.4.11 and containerd 1.5.7. Users should update to these version when they are
    released and may restart containers or update directory permissions to mitigate the vulnerability. Users
    unable to update should limit access to the host to trusted users. Update directory permission on
    container bundles directories. (CVE-2021-41103)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/containerd");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5002");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41103");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/containerd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the containerd packages.

For the stable distribution (bullseye), this problem has been fixed in version 1.4.5~ds1-2+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41103");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-github-containerd-containerd-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'containerd', 'reference': '1.4.5~ds1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'golang-github-containerd-containerd-dev', 'reference': '1.4.5~ds1-2+deb11u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containerd / golang-github-containerd-containerd-dev');
}
