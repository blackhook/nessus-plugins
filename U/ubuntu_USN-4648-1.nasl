##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4648-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143269);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-9948",
    "CVE-2020-9951",
    "CVE-2020-9952",
    "CVE-2020-9983",
    "CVE-2020-13753"
  );
  script_xref(name:"USN", value:"4648-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 : WebKitGTK vulnerabilities (USN-4648-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4648-1 advisory.

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9948)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9951)

  - An input validation issue was addressed with improved input validation. This issue is fixed in iOS 14.0
    and iPadOS 14.0, tvOS 14.0, watchOS 7.0, Safari 14.0, iCloud for Windows 11.4, iCloud for Windows 7.21.
    Processing maliciously crafted web content may lead to a cross site scripting attack. (CVE-2020-9952)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in Safari
    14.0. Processing maliciously crafted web content may lead to code execution. (CVE-2020-9983)

  - The bubblewrap sandbox of WebKitGTK and WPE WebKit, prior to 2.28.3, failed to properly block access to
    CLONE_NEWUSER and the TIOCSTI ioctl. CLONE_NEWUSER could potentially be used to confuse xdg-desktop-
    portal, which allows access outside the sandbox. TIOCSTI can be used to directly execute commands outside
    the sandbox by writing to the controlling terminal's input buffer, similar to CVE-2017-5226.
    (CVE-2020-13753)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4648-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13753");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-javascriptcoregtk-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-webkit2-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.0-37-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit2gtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:webkit2gtk-driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'gir1.2-javascriptcoregtk-4.0', 'pkgver': '2.30.3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'gir1.2-webkit2-4.0', 'pkgver': '2.30.3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libjavascriptcoregtk-4.0-18', 'pkgver': '2.30.3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libjavascriptcoregtk-4.0-bin', 'pkgver': '2.30.3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libjavascriptcoregtk-4.0-dev', 'pkgver': '2.30.3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libwebkit2gtk-4.0-37', 'pkgver': '2.30.3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libwebkit2gtk-4.0-37-gtk2', 'pkgver': '2.30.3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libwebkit2gtk-4.0-dev', 'pkgver': '2.30.3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'webkit2gtk-driver', 'pkgver': '2.30.3-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-javascriptcoregtk-4.0', 'pkgver': '2.30.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-webkit2-4.0', 'pkgver': '2.30.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libjavascriptcoregtk-4.0-18', 'pkgver': '2.30.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libjavascriptcoregtk-4.0-bin', 'pkgver': '2.30.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libjavascriptcoregtk-4.0-dev', 'pkgver': '2.30.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwebkit2gtk-4.0-37', 'pkgver': '2.30.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwebkit2gtk-4.0-37-gtk2', 'pkgver': '2.30.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libwebkit2gtk-4.0-dev', 'pkgver': '2.30.3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'webkit2gtk-driver', 'pkgver': '2.30.3-0ubuntu0.20.04.1'},
    {'osver': '20.10', 'pkgname': 'gir1.2-javascriptcoregtk-4.0', 'pkgver': '2.30.3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'gir1.2-webkit2-4.0', 'pkgver': '2.30.3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libjavascriptcoregtk-4.0-18', 'pkgver': '2.30.3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libjavascriptcoregtk-4.0-bin', 'pkgver': '2.30.3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libjavascriptcoregtk-4.0-dev', 'pkgver': '2.30.3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libwebkit2gtk-4.0-37', 'pkgver': '2.30.3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libwebkit2gtk-4.0-37-gtk2', 'pkgver': '2.30.3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libwebkit2gtk-4.0-dev', 'pkgver': '2.30.3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'webkit2gtk-driver', 'pkgver': '2.30.3-0ubuntu0.20.10.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-javascriptcoregtk-4.0 / gir1.2-webkit2-4.0 / etc');
}