#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5398. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175125);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id(
    "CVE-2023-2459",
    "CVE-2023-2460",
    "CVE-2023-2461",
    "CVE-2023-2462",
    "CVE-2023-2463",
    "CVE-2023-2464",
    "CVE-2023-2465",
    "CVE-2023-2466",
    "CVE-2023-2467",
    "CVE-2023-2468"
  );
  script_xref(name:"IAVA", value:"2023-A-0236-S");

  script_name(english:"Debian DSA-5398-1 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5398 advisory.

  - Inappropriate implementation in Prompts in Google Chrome prior to 113.0.5672.63 allowed a remote attacker
    to bypass permission restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-2459)

  - Insufficient validation of untrusted input in Extensions in Google Chrome prior to 113.0.5672.63 allowed
    an attacker who convinced a user to install a malicious extension to bypass file access checks via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2023-2460)

  - Use after free in OS Inputs in Google Chrome on ChromeOS prior to 113.0.5672.63 allowed a remote attacker
    who convinced a user to enage in specific UI interaction to potentially exploit heap corruption via
    crafted UI interaction. (Chromium security severity: Medium) (CVE-2023-2461)

  - Inappropriate implementation in Prompts in Google Chrome prior to 113.0.5672.63 allowed a remote attacker
    to obfuscate main origin data via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-2462)

  - Inappropriate implementation in Full Screen Mode in Google Chrome on Android prior to 113.0.5672.63
    allowed a remote attacker to hide the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-2463)

  - Inappropriate implementation in PictureInPicture in Google Chrome prior to 113.0.5672.63 allowed an
    attacker who convinced a user to install a malicious extension to perform an origin spoof in the security
    UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-2464)

  - Inappropriate implementation in CORS in Google Chrome prior to 113.0.5672.63 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-2465)

  - Inappropriate implementation in Prompts in Google Chrome prior to 113.0.5672.63 allowed a remote attacker
    to spoof the contents of the security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-2466)

  - Inappropriate implementation in Prompts in Google Chrome on Android prior to 113.0.5672.63 allowed a
    remote attacker to bypass permissions restrictions via a crafted HTML page. (Chromium security severity:
    Low) (CVE-2023-2467)

  - Inappropriate implementation in PictureInPicture in Google Chrome prior to 113.0.5672.63 allowed a remote
    attacker who had compromised the renderer process to obfuscate the security UI via a crafted HTML page.
    (Chromium security severity: Low) (CVE-2023-2468)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=992178");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5398");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2459");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2460");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2461");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2462");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2463");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2464");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2465");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2466");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2467");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2468");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.

For the stable distribution (bullseye), these problems have been fixed in version 113.0.5672.63-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2461");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-shell");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '11.0', 'prefix': 'chromium', 'reference': '113.0.5672.63-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-common', 'reference': '113.0.5672.63-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-driver', 'reference': '113.0.5672.63-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-l10n', 'reference': '113.0.5672.63-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-sandbox', 'reference': '113.0.5672.63-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-shell', 'reference': '113.0.5672.63-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium / chromium-common / chromium-driver / chromium-l10n / etc');
}
