#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5396. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175077);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id(
    "CVE-2022-0108",
    "CVE-2022-32885",
    "CVE-2023-27932",
    "CVE-2023-27954",
    "CVE-2023-28205"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/01");

  script_name(english:"Debian DSA-5396-1 : webkit2gtk - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5396 advisory.

  - Inappropriate implementation in Navigation in Google Chrome prior to 97.0.4692.71 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-0108)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 15.7.5
    and iPadOS 15.7.5, Safari 16.4.1, iOS 16.4.1 and iPadOS 16.4.1, macOS Ventura 13.3.1. Processing
    maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this
    issue may have been actively exploited. (CVE-2023-28205)

  -  * The Bubblewrap sandbox no longer requires setting an application identifier via GApplication to operate
    correctly. Using GApplication is still recommended, but optional.  * Adjust the scrolling speed for mouse
    wheels to make it feel more natural.  * Allow pasting content using the Asynchronous Clipboard API when
    the origin is the same as the clipboard contents.  * Improvements to the GStreamer multimedia playback, in
    particular around MSE, WebRTC, and seeking.  * Make all supported image types appear in the Accept HTTP
    header.  * Fix text caret blinking when blinking is disabled in the GTK settings.  * Fix default database
    quota size definition.  * Fix application of all caps tags listed in the font-feature-settings CSS
    property.  * Fix font height calculations for the font-size-adjust CSS property.  * Fix several crashes
    and rendering issues.  * Security fixes: CVE-2022-0108, CVE-2022-32885, CVE-2023-25358, CVE-2023-27932,
    CVE-2023-27954, CVE-2023-28205  (CVE-2022-32885)

  - This issue was addressed with improved state management. (CVE-2023-27932)

  - The issue was addressed by removing origin information. (CVE-2023-27954)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/webkit2gtk");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5396");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0108");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32885");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27932");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27954");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28205");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/webkit2gtk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the webkit2gtk packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.40.1-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0108");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28205");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-javascriptcoregtk-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-webkit2-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webkit2gtk-driver");
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
    {'release': '11.0', 'prefix': 'gir1.2-javascriptcoregtk-4.0', 'reference': '2.40.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'gir1.2-webkit2-4.0', 'reference': '2.40.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libjavascriptcoregtk-4.0-18', 'reference': '2.40.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libjavascriptcoregtk-4.0-bin', 'reference': '2.40.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libjavascriptcoregtk-4.0-dev', 'reference': '2.40.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwebkit2gtk-4.0-37', 'reference': '2.40.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwebkit2gtk-4.0-dev', 'reference': '2.40.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libwebkit2gtk-4.0-doc', 'reference': '2.40.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'webkit2gtk-driver', 'reference': '2.40.1-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-javascriptcoregtk-4.0 / gir1.2-webkit2-4.0 / etc');
}
