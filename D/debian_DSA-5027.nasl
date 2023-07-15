#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5027. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156233);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id(
    "CVE-2021-4008",
    "CVE-2021-4009",
    "CVE-2021-4010",
    "CVE-2021-4011"
  );

  script_name(english:"Debian DSA-5027-1 : xorg-server - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5027 advisory.

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcRenderCompositeGlyphs function. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2021-4008)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcXFixesCreatePointerBarrier function. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system availability. (CVE-2021-4009)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcScreenSaverSuspend function. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2021-4010)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SwapCreateRegister function. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2021-4011)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xorg-server");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5027");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4008");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4009");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4010");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4011");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/xorg-server");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/xorg-server");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xorg-server packages.

For the stable distribution (bullseye), these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4011");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-core-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xwayland");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'xdmx', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xdmx-tools', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xnest', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xorg-server-source', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xserver-common', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xserver-xephyr', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xserver-xorg-core', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xserver-xorg-core-udeb', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xserver-xorg-dev', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xserver-xorg-legacy', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xvfb', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '10.0', 'prefix': 'xwayland', 'reference': '2:1.20.4-1+deb10u4'},
    {'release': '11.0', 'prefix': 'xdmx', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xdmx-tools', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xnest', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xorg-server-source', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xserver-common', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xserver-xephyr', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xserver-xorg-core', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xserver-xorg-core-udeb', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xserver-xorg-dev', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xserver-xorg-legacy', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xvfb', 'reference': '2:1.20.11-1+deb11u1'},
    {'release': '11.0', 'prefix': 'xwayland', 'reference': '2:1.20.11-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xnest / xorg-server-source / xserver-common / etc');
}
