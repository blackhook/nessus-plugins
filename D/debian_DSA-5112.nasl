#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5112. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159510);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-1125",
    "CVE-2022-1127",
    "CVE-2022-1128",
    "CVE-2022-1129",
    "CVE-2022-1130",
    "CVE-2022-1131",
    "CVE-2022-1132",
    "CVE-2022-1133",
    "CVE-2022-1134",
    "CVE-2022-1135",
    "CVE-2022-1136",
    "CVE-2022-1137",
    "CVE-2022-1138",
    "CVE-2022-1139",
    "CVE-2022-1141",
    "CVE-2022-1142",
    "CVE-2022-1143",
    "CVE-2022-1144",
    "CVE-2022-1145",
    "CVE-2022-1146"
  );

  script_name(english:"Debian DSA-5112-1 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5112 advisory.

  - Use after free in Extensions in Google Chrome prior to 100.0.4896.60 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific user interaction
    and profile destruction. (CVE-2022-1145)

  - Use after free in Portals in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced
    a user to engage in specific user interaction to potentially exploit heap corruption via user interaction.
    (CVE-2022-1125)

  - Use after free in QR Code Generator in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via user
    interaction. (CVE-2022-1127)

  - Inappropriate implementation in Web Share API in Google Chrome on Windows prior to 100.0.4896.60 allowed
    an attacker on the local network segment to leak cross-origin data via a crafted HTML page.
    (CVE-2022-1128)

  - Inappropriate implementation in Full Screen Mode in Google Chrome on Android prior to 100.0.4896.60
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (CVE-2022-1129)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5112");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1125");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1127");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1128");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1129");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1130");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1131");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1132");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1133");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1134");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1135");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1136");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1137");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1138");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1139");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1141");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1142");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1143");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1144");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1145");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1146");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.

For the stable distribution (bullseye), these problems have been fixed in version 100.0.4896.60-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1145");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-shell");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'chromium', 'reference': '100.0.4896.60-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-common', 'reference': '100.0.4896.60-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-driver', 'reference': '100.0.4896.60-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-l10n', 'reference': '100.0.4896.60-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-sandbox', 'reference': '100.0.4896.60-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-shell', 'reference': '100.0.4896.60-1~deb11u1'}
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
