#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5228. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164943);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/12");

  script_cve_id("CVE-2021-44648", "CVE-2021-46829");

  script_name(english:"Debian DSA-5228-1 : gdk-pixbuf - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5228 advisory.

  - GNOME gdk-pixbuf 2.42.6 is vulnerable to a heap-buffer overflow vulnerability when decoding the lzw
    compressed stream of image data in GIF files with lzw minimum code size equals to 12. (CVE-2021-44648)

  - GNOME GdkPixbuf (aka GDK-PixBuf) before 2.42.8 allows a heap-based buffer overflow when compositing or
    clearing frames in GIF files, as demonstrated by io-gif-animation.c composite_frame. This overflow is
    controllable and could be abused for code execution, especially on 32-bit systems. (CVE-2021-46829)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1014600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/gdk-pixbuf");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5228");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44648");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46829");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/gdk-pixbuf");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gdk-pixbuf packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.42.2+dfsg-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44648");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gdk-pixbuf-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gdkpixbuf-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf-2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf-2.0-0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgdk-pixbuf2.0-doc");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'gdk-pixbuf-tests', 'reference': '2.42.2+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'gir1.2-gdkpixbuf-2.0', 'reference': '2.42.2+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libgdk-pixbuf-2.0-0', 'reference': '2.42.2+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libgdk-pixbuf-2.0-0-udeb', 'reference': '2.42.2+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libgdk-pixbuf-2.0-dev', 'reference': '2.42.2+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libgdk-pixbuf2.0-0-udeb', 'reference': '2.42.2+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libgdk-pixbuf2.0-bin', 'reference': '2.42.2+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libgdk-pixbuf2.0-common', 'reference': '2.42.2+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libgdk-pixbuf2.0-doc', 'reference': '2.42.2+dfsg-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gdk-pixbuf-tests / gir1.2-gdkpixbuf-2.0 / libgdk-pixbuf-2.0-0 / etc');
}
