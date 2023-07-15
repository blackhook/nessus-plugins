#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5366. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172051);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/03");

  script_cve_id("CVE-2022-41973", "CVE-2022-41974");

  script_name(english:"Debian DSA-5366-1 : multipath-tools - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5366 advisory.

  - multipath-tools 0.7.7 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited in
    conjunction with CVE-2022-41974. Local users able to access /dev/shm can change symlinks in multipathd due
    to incorrect symlink handling, which could lead to controlled file writes outside of the /dev/shm
    directory. This could be used indirectly for local privilege escalation to root. (CVE-2022-41973)

  - multipath-tools 0.7.0 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited
    alone or in conjunction with CVE-2022-41973. Local users able to write to UNIX domain sockets can bypass
    access controls and manipulate the multipath setup. This can lead to local privilege escalation to root.
    This occurs because an attacker can repeat a keyword, which is mishandled because arithmetic ADD is used
    instead of bitwise OR. (CVE-2022-41974)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1022742");
  # https://security-tracker.debian.org/tracker/source-package/multipath-tools
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83ad3989");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5366");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41973");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41974");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/multipath-tools");
  script_set_attribute(attribute:"solution", value:
"Upgrade the multipath-tools packages.

For the stable distribution (bullseye), these problems have been fixed in version 0.8.5-2+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41974");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kpartx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kpartx-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-tools-boot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'kpartx', 'reference': '0.8.5-2+deb11u1'},
    {'release': '11.0', 'prefix': 'kpartx-udeb', 'reference': '0.8.5-2+deb11u1'},
    {'release': '11.0', 'prefix': 'multipath-tools', 'reference': '0.8.5-2+deb11u1'},
    {'release': '11.0', 'prefix': 'multipath-tools-boot', 'reference': '0.8.5-2+deb11u1'},
    {'release': '11.0', 'prefix': 'multipath-udeb', 'reference': '0.8.5-2+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kpartx / kpartx-udeb / multipath-tools / multipath-tools-boot / etc');
}
