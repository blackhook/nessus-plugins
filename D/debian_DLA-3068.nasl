#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3068. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(163851);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-2319", "CVE-2022-2320");

  script_name(english:"Debian DLA-3068-1 : xorg-server - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3068 advisory.

  - A flaw was found in the Xorg-x11-server. The specific flaw exists within the handling of
    ProcXkbSetDeviceInfo requests. The issue results from the lack of proper validation of user-supplied data,
    which can result in a memory access past the end of an allocated buffer. This flaw allows an attacker to
    escalate privileges and execute arbitrary code in the context of root. (CVE-2022-2320)

  - A flaw was found in the Xorg-x11-server. An out-of-bounds access issue can occur in the ProcXkbSetGeometry
    function due to improper validation of the request length. (CVE-2022-2319)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xorg-server");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3068");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2319");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2320");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/xorg-server");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xorg-server packages.

For Debian 10 buster, these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2320");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xwayland");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'xdmx', 'reference': '2:1.20.4-1+deb10u5'},
    {'release': '10.0', 'prefix': 'xdmx-tools', 'reference': '2:1.20.4-1+deb10u5'},
    {'release': '10.0', 'prefix': 'xnest', 'reference': '2:1.20.4-1+deb10u5'},
    {'release': '10.0', 'prefix': 'xorg-server-source', 'reference': '2:1.20.4-1+deb10u5'},
    {'release': '10.0', 'prefix': 'xserver-common', 'reference': '2:1.20.4-1+deb10u5'},
    {'release': '10.0', 'prefix': 'xserver-xephyr', 'reference': '2:1.20.4-1+deb10u5'},
    {'release': '10.0', 'prefix': 'xserver-xorg-core', 'reference': '2:1.20.4-1+deb10u5'},
    {'release': '10.0', 'prefix': 'xserver-xorg-dev', 'reference': '2:1.20.4-1+deb10u5'},
    {'release': '10.0', 'prefix': 'xserver-xorg-legacy', 'reference': '2:1.20.4-1+deb10u5'},
    {'release': '10.0', 'prefix': 'xvfb', 'reference': '2:1.20.4-1+deb10u5'},
    {'release': '10.0', 'prefix': 'xwayland', 'reference': '2:1.20.4-1+deb10u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xnest / xorg-server-source / xserver-common / etc');
}
