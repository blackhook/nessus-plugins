#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5949-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172511);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id(
    "CVE-2023-0928",
    "CVE-2023-0929",
    "CVE-2023-0930",
    "CVE-2023-0931",
    "CVE-2023-0933",
    "CVE-2023-0941",
    "CVE-2023-1213",
    "CVE-2023-1214",
    "CVE-2023-1215",
    "CVE-2023-1216",
    "CVE-2023-1218",
    "CVE-2023-1219",
    "CVE-2023-1220",
    "CVE-2023-1221",
    "CVE-2023-1222",
    "CVE-2023-1224",
    "CVE-2023-1226",
    "CVE-2023-1229",
    "CVE-2023-1232",
    "CVE-2023-1233",
    "CVE-2023-1235",
    "CVE-2023-1236"
  );
  script_xref(name:"USN", value:"5949-1");
  script_xref(name:"IAVA", value:"2023-A-0131-S");

  script_name(english:"Ubuntu 18.04 LTS : Chromium vulnerabilities (USN-5949-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5949-1 advisory.

  - Use after free in SwiftShader in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-0928)

  - Use after free in Vulkan in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0929)

  - Heap buffer overflow in Video in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-0930)

  - Use after free in Video in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0931)

  - Integer overflow in PDF in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (Chromium security severity: Medium) (CVE-2023-0933)

  - Use after free in Prompts in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2023-0941)

  - Use after free in Swiftshader in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-1213)

  - Type confusion in V8 in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1214)

  - Type confusion in CSS in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1215)

  - Use after free in DevTools in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    convienced the user to engage in direct UI interaction to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: High) (CVE-2023-1216)

  - Use after free in WebRTC in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1218)

  - Heap buffer overflow in Metrics in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1219)

  - Heap buffer overflow in UMA in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1220)

  - Insufficient policy enforcement in Extensions API in Google Chrome prior to 111.0.5563.64 allowed an
    attacker who convinced a user to install a malicious extension to bypass navigation restrictions via a
    crafted Chrome Extension. (Chromium security severity: Medium) (CVE-2023-1221)

  - Heap buffer overflow in Web Audio API in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1222)

  - Insufficient policy enforcement in Web Payments API in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1224)

  - Insufficient policy enforcement in Web Payments API in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to bypass content security policy via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1226)

  - Inappropriate implementation in Permission prompts in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1229)

  - Insufficient policy enforcement in Resource Timing in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to obtain potentially sensitive information from API via a crafted HTML page. (Chromium
    security severity: Low) (CVE-2023-1232)

  - Insufficient policy enforcement in Resource Timing in Google Chrome prior to 111.0.5563.64 allowed an
    attacker who convinced a user to install a malicious extension to obtain potentially sensitive information
    from API via a crafted Chrome Extension. (Chromium security severity: Low) (CVE-2023-1233)

  - Type confusion in DevTools in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted UI interaction.
    (Chromium security severity: Low) (CVE-2023-1235)

  - Inappropriate implementation in Internals in Google Chrome prior to 111.0.5563.64 allowed a remote
    attacker to spoof the origin of an iframe via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-1236)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5949-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0941");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-1222");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:chromium-browser-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:chromium-chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:chromium-codecs-ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:chromium-codecs-ffmpeg-extra");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(18\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'chromium-browser', 'pkgver': '111.0.5563.64-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'chromium-browser-l10n', 'pkgver': '111.0.5563.64-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'chromium-chromedriver', 'pkgver': '111.0.5563.64-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'chromium-codecs-ffmpeg', 'pkgver': '111.0.5563.64-0ubuntu0.18.04.5'},
    {'osver': '18.04', 'pkgname': 'chromium-codecs-ffmpeg-extra', 'pkgver': '111.0.5563.64-0ubuntu0.18.04.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium-browser / chromium-browser-l10n / chromium-chromedriver / etc');
}
