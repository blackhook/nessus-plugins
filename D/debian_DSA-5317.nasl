#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5317. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170047);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/14");

  script_cve_id(
    "CVE-2023-0128",
    "CVE-2023-0129",
    "CVE-2023-0130",
    "CVE-2023-0131",
    "CVE-2023-0132",
    "CVE-2023-0133",
    "CVE-2023-0134",
    "CVE-2023-0135",
    "CVE-2023-0136",
    "CVE-2023-0137",
    "CVE-2023-0138",
    "CVE-2023-0139",
    "CVE-2023-0140",
    "CVE-2023-0141"
  );

  script_name(english:"Debian DSA-5317-1 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5317 advisory.

  - Use after free in Overview Mode in Google Chrome on Chrome OS prior to 109.0.5414.74 allowed a remote
    attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption
    via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0128)

  - Heap buffer overflow in Network Service in Google Chrome prior to 109.0.5414.74 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    HTML page and specific interactions. (Chromium security severity: High) (CVE-2023-0129)

  - Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (Chromium security severity: Medium) (CVE-2023-0130)

  - Inappropriate implementation in in iframe Sandbox in Google Chrome prior to 109.0.5414.74 allowed a remote
    attacker to bypass file download restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-0131)

  - Inappropriate implementation in in Permission prompts in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to force acceptance of a permission prompt via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-0132)

  - Inappropriate implementation in in Permission prompts in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to bypass main origin permission delegation via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-0133)

  - Use after free in Cart in Google Chrome prior to 109.0.5414.74 allowed an attacker who convinced a user to
    install a malicious extension to potentially exploit heap corruption via database corruption and a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-0134, CVE-2023-0135)

  - Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to execute incorrect security UI via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-0136)

  - Heap buffer overflow in Platform Apps in Google Chrome on Chrome OS prior to 109.0.5414.74 allowed an
    attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via
    a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-0137)

  - Heap buffer overflow in libphonenumber in Google Chrome prior to 109.0.5414.74 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-0138)

  - Insufficient validation of untrusted input in Downloads in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to bypass download restrictions via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0139)

  - Inappropriate implementation in in File System API in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0140)

  - Insufficient policy enforcement in CORS in Google Chrome prior to 109.0.5414.74 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-0141)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5317");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0128");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0129");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0130");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0131");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0132");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0133");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0134");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0135");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0136");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0137");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0138");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0139");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0140");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0141");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.

For the stable distribution (bullseye), this problem has been fixed in version 109.0.5414.74-2~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0135");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-0138");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/14");

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
    {'release': '11.0', 'prefix': 'chromium', 'reference': '109.0.5414.74-2~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-common', 'reference': '109.0.5414.74-2~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-driver', 'reference': '109.0.5414.74-2~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-l10n', 'reference': '109.0.5414.74-2~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-sandbox', 'reference': '109.0.5414.74-2~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-shell', 'reference': '109.0.5414.74-2~deb11u1'}
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
