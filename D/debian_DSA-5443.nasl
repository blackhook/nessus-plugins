#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5443. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177887);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/02");

  script_name(english:"Debian DSA-5443-1 : gst-plugins-base1.0 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5443
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/gst-plugins-base1.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43b9aaa1");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5443");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/gst-plugins-base1.0");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/gst-plugins-base1.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gst-plugins-base1.0 packages.

For the stable distribution (bookworm), this problem has been fixed in version 1.22.0-3+deb12u1.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gst-plugins-base-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-base-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-gl1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-base1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-base1.0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'gir1.2-gst-plugins-base-1.0', 'reference': '1.18.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'gstreamer1.0-alsa', 'reference': '1.18.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'gstreamer1.0-gl', 'reference': '1.18.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'gstreamer1.0-plugins-base', 'reference': '1.18.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'gstreamer1.0-plugins-base-apps', 'reference': '1.18.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'gstreamer1.0-x', 'reference': '1.18.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libgstreamer-gl1.0-0', 'reference': '1.18.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libgstreamer-plugins-base1.0-0', 'reference': '1.18.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libgstreamer-plugins-base1.0-dev', 'reference': '1.18.4-2+deb11u1'},
    {'release': '12.0', 'prefix': 'gir1.2-gst-plugins-base-1.0', 'reference': '1.22.0-3+deb12u1'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-alsa', 'reference': '1.22.0-3+deb12u1'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-gl', 'reference': '1.22.0-3+deb12u1'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-plugins-base', 'reference': '1.22.0-3+deb12u1'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-plugins-base-apps', 'reference': '1.22.0-3+deb12u1'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-x', 'reference': '1.22.0-3+deb12u1'},
    {'release': '12.0', 'prefix': 'libgstreamer-gl1.0-0', 'reference': '1.22.0-3+deb12u1'},
    {'release': '12.0', 'prefix': 'libgstreamer-plugins-base1.0-0', 'reference': '1.22.0-3+deb12u1'},
    {'release': '12.0', 'prefix': 'libgstreamer-plugins-base1.0-dev', 'reference': '1.22.0-3+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-gst-plugins-base-1.0 / gstreamer1.0-alsa / gstreamer1.0-gl / etc');
}
