#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5797-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169734);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-42852",
    "CVE-2022-42856",
    "CVE-2022-42867",
    "CVE-2022-46692",
    "CVE-2022-46698",
    "CVE-2022-46699",
    "CVE-2022-46700"
  );
  script_xref(name:"USN", value:"5797-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/04");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 : WebKitGTK vulnerabilities (USN-5797-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5797-1 advisory.

  - The issue was addressed with improved memory handling. This issue is fixed in Safari 16.2, tvOS 16.2,
    macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing
    maliciously crafted web content may result in the disclosure of process memory. (CVE-2022-42852)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in Safari 16.2,
    tvOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.1.2. Processing maliciously crafted
    web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been
    actively exploited against versions of iOS released before iOS 15.1.. (CVE-2022-42856)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 16.2,
    tvOS 16.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-42867)

  - A logic issue was addressed with improved state management. This issue is fixed in Safari 16.2, tvOS 16.2,
    iCloud for Windows 14.1, iOS 15.7.2 and iPadOS 15.7.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2,
    watchOS 9.2. Processing maliciously crafted web content may bypass Same Origin Policy. (CVE-2022-46692)

  - A logic issue was addressed with improved checks. This issue is fixed in Safari 16.2, tvOS 16.2, iCloud
    for Windows 14.1, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing maliciously
    crafted web content may disclose sensitive user information. (CVE-2022-46698)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in Safari
    16.2, tvOS 16.2, macOS Ventura 13.1, iOS 16.2 and iPadOS 16.2, watchOS 9.2. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2022-46699)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in Safari
    16.2, tvOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2022-46700)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5797-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46700");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-javascriptcoregtk-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-javascriptcoregtk-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-javascriptcoregtk-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-webkit2-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-webkit2-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-webkit2-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-5.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-5.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.0-37-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-5.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-5.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:webkit2gtk-driver");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'gir1.2-javascriptcoregtk-4.0', 'pkgver': '2.38.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-webkit2-4.0', 'pkgver': '2.38.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libjavascriptcoregtk-4.0-18', 'pkgver': '2.38.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libjavascriptcoregtk-4.0-bin', 'pkgver': '2.38.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libjavascriptcoregtk-4.0-dev', 'pkgver': '2.38.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwebkit2gtk-4.0-37', 'pkgver': '2.38.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwebkit2gtk-4.0-37-gtk2', 'pkgver': '2.38.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwebkit2gtk-4.0-dev', 'pkgver': '2.38.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'webkit2gtk-driver', 'pkgver': '2.38.3-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-javascriptcoregtk-4.0', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-javascriptcoregtk-4.1', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-webkit2-4.0', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-webkit2-4.1', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libjavascriptcoregtk-4.0-18', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libjavascriptcoregtk-4.0-bin', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libjavascriptcoregtk-4.0-dev', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libjavascriptcoregtk-4.1-0', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libjavascriptcoregtk-4.1-dev', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libwebkit2gtk-4.0-37', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libwebkit2gtk-4.0-dev', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libwebkit2gtk-4.1-0', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libwebkit2gtk-4.1-dev', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'webkit2gtk-driver', 'pkgver': '2.38.3-0ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'gir1.2-javascriptcoregtk-4.0', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'gir1.2-javascriptcoregtk-4.1', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'gir1.2-javascriptcoregtk-5.0', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'gir1.2-webkit2-4.0', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'gir1.2-webkit2-4.1', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'gir1.2-webkit2-5.0', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libjavascriptcoregtk-4.0-18', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libjavascriptcoregtk-4.0-bin', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libjavascriptcoregtk-4.0-dev', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libjavascriptcoregtk-4.1-0', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libjavascriptcoregtk-4.1-dev', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libjavascriptcoregtk-5.0-0', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libjavascriptcoregtk-5.0-dev', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libwebkit2gtk-4.0-37', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libwebkit2gtk-4.0-dev', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libwebkit2gtk-4.1-0', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libwebkit2gtk-4.1-dev', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libwebkit2gtk-5.0-0', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libwebkit2gtk-5.0-dev', 'pkgver': '2.38.3-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'webkit2gtk-driver', 'pkgver': '2.38.3-0ubuntu0.22.10.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-javascriptcoregtk-4.0 / gir1.2-javascriptcoregtk-4.1 / etc');
}
