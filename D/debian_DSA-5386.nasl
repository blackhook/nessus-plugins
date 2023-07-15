#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5386. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174250);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id(
    "CVE-2023-1810",
    "CVE-2023-1811",
    "CVE-2023-1812",
    "CVE-2023-1813",
    "CVE-2023-1814",
    "CVE-2023-1815",
    "CVE-2023-1816",
    "CVE-2023-1817",
    "CVE-2023-1818",
    "CVE-2023-1819",
    "CVE-2023-1820",
    "CVE-2023-1821",
    "CVE-2023-1822",
    "CVE-2023-1823"
  );

  script_name(english:"Debian DSA-5386-1 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5386 advisory.

  - Heap buffer overflow in Visuals in Google Chrome prior to 112.0.5615.49 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1810)

  - Use after free in Frames in Google Chrome prior to 112.0.5615.49 allowed a remote attacker who convinced a
    user to engage in specific UI interaction to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-1811)

  - Out of bounds memory access in DOM Bindings in Google Chrome prior to 112.0.5615.49 allowed a remote
    attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1812)

  - Inappropriate implementation in Extensions in Google Chrome prior to 112.0.5615.49 allowed an attacker who
    convinced a user to install a malicious extension to bypass file access restrictions via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2023-1813)

  - Insufficient validation of untrusted input in Safe Browsing in Google Chrome prior to 112.0.5615.49
    allowed a remote attacker to bypass download checking via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-1814)

  - Use after free in Networking APIs in Google Chrome prior to 112.0.5615.49 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-1815)

  - Incorrect security UI in Picture In Picture in Google Chrome prior to 112.0.5615.49 allowed a remote
    attacker to potentially perform navigation spoofing via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1816)

  - Insufficient policy enforcement in Intents in Google Chrome on Android prior to 112.0.5615.49 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1817)

  - Use after free in Vulkan in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-1818)

  - Out of bounds read in Accessibility in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to
    perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1819)

  - Heap buffer overflow in Browser History in Google Chrome prior to 112.0.5615.49 allowed a remote attacker
    who convinced a user to engage in specific UI interaction to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2023-1820)

  - Inappropriate implementation in WebShare in Google Chrome prior to 112.0.5615.49 allowed a remote attacker
    to potentially hide the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-1821)

  - Incorrect security UI in Navigation in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to
    perform domain spoofing via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-1822)

  - Inappropriate implementation in FedCM in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to
    bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-1823)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5386");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1810");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1811");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1812");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1813");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1814");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1815");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1816");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1817");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1818");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1819");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1820");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1821");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1822");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1823");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.

For the stable distribution (bullseye), these problems have been fixed in version 112.0.5615.49-2~deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1818");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-1820");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-shell");
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
    {'release': '11.0', 'prefix': 'chromium', 'reference': '112.0.5615.49-2~deb11u2'},
    {'release': '11.0', 'prefix': 'chromium-common', 'reference': '112.0.5615.49-2~deb11u2'},
    {'release': '11.0', 'prefix': 'chromium-driver', 'reference': '112.0.5615.49-2~deb11u2'},
    {'release': '11.0', 'prefix': 'chromium-l10n', 'reference': '112.0.5615.49-2~deb11u2'},
    {'release': '11.0', 'prefix': 'chromium-sandbox', 'reference': '112.0.5615.49-2~deb11u2'},
    {'release': '11.0', 'prefix': 'chromium-shell', 'reference': '112.0.5615.49-2~deb11u2'}
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
