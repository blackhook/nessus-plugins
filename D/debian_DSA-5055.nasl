#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5055. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157263);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-3995", "CVE-2021-3996");

  script_name(english:"Debian DSA-5055-1 : util-linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5055 advisory.

  - A logic error was found in the libmount library of util-linux in the function that allows an unprivileged
    user to unmount a FUSE filesystem. This flaw allows a local user on a vulnerable system to unmount other
    users' filesystems that are either world-writable themselves (like /tmp) or mounted in a world-writable
    directory. An attacker may use this flaw to cause a denial of service to applications that use the
    affected filesystems. (CVE-2021-3996)

  - A logic error was found in the libmount library of util-linux in the function that allows an unprivileged
    user to unmount a FUSE filesystem. This flaw allows an unprivileged local attacker to unmount FUSE
    filesystems that belong to certain other users who have a UID that is a prefix of the UID of the attacker
    in its string form. An attacker may use this flaw to cause a denial of service to applications that use
    the affected filesystems. (CVE-2021-3995)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/util-linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5055");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3995");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3996");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/util-linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the util-linux packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.36.1-8+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdextrautils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eject-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fdisk-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libblkid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libblkid1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfdisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfdisk1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmount-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmount1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmartcols-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmartcols1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuuid1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rfkill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uuid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uuid-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'bsdextrautils', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'bsdutils', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'eject', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'eject-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'fdisk', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'fdisk-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libblkid-dev', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libblkid1', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libblkid1-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libfdisk-dev', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libfdisk1', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libfdisk1-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libmount-dev', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libmount1', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libmount1-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libsmartcols-dev', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libsmartcols1', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libsmartcols1-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libuuid1', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libuuid1-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'mount', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'rfkill', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'util-linux', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'util-linux-locales', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'util-linux-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'uuid-dev', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'uuid-runtime', 'reference': '2.36.1-8+deb11u1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bsdextrautils / bsdutils / eject / eject-udeb / fdisk / fdisk-udeb / etc');
}
