#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5244. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165594);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/03");

  script_cve_id(
    "CVE-2022-3201",
    "CVE-2022-3304",
    "CVE-2022-3305",
    "CVE-2022-3306",
    "CVE-2022-3307",
    "CVE-2022-3308",
    "CVE-2022-3309",
    "CVE-2022-3310",
    "CVE-2022-3311",
    "CVE-2022-3312",
    "CVE-2022-3313",
    "CVE-2022-3314",
    "CVE-2022-3315",
    "CVE-2022-3316",
    "CVE-2022-3317",
    "CVE-2022-3318"
  );
  script_xref(name:"IAVA", value:"2022-A-0394-S");

  script_name(english:"Debian DSA-5244-1 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5244 advisory.

  - Insufficient validation of untrusted input in DevTools in Google Chrome on Chrome OS prior to
    105.0.5195.125 allowed an attacker who convinced a user to install a malicious extension to bypass
    navigation restrictions via a crafted HTML page. (CVE-2022-3201)

  - Use after free in CSS. (CVE-2022-3304)

  - Use after free in Survey. (CVE-2022-3305, CVE-2022-3306)

  - Use after free in Media. (CVE-2022-3307)

  - Insufficient policy enforcement in Developer Tools. (CVE-2022-3308)

  - Use after free in Assistant. (CVE-2022-3309)

  - Insufficient policy enforcement in Custom Tabs. (CVE-2022-3310)

  - Use after free in Import. (CVE-2022-3311)

  - Insufficient validation of untrusted input in VPN. (CVE-2022-3312)

  - Incorrect security UI in Full Screen. (CVE-2022-3313)

  - Use after free in Logging. (CVE-2022-3314)

  - Type confusion in Blink. (CVE-2022-3315)

  - Insufficient validation of untrusted input in Safe Browsing. (CVE-2022-3316)

  - Insufficient validation of untrusted input in Intents. (CVE-2022-3317)

  - Use after free in ChromeOS Notifications. (CVE-2022-3318)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3201");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3304");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3305");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3306");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3307");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3308");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3309");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3310");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3311");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3312");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3313");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3314");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3315");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3316");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3317");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3318");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.

For the stable distribution (bullseye), these problems have been fixed in version 106.0.5249.61-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3318");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-shell");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '11.0', 'prefix': 'chromium', 'reference': '106.0.5249.61-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-common', 'reference': '106.0.5249.61-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-driver', 'reference': '106.0.5249.61-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-l10n', 'reference': '106.0.5249.61-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-sandbox', 'reference': '106.0.5249.61-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-shell', 'reference': '106.0.5249.61-1~deb11u1'}
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
