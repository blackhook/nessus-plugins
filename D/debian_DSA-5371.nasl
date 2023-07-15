#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5371. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172448);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id(
    "CVE-2023-1213",
    "CVE-2023-1214",
    "CVE-2023-1215",
    "CVE-2023-1216",
    "CVE-2023-1217",
    "CVE-2023-1218",
    "CVE-2023-1219",
    "CVE-2023-1220",
    "CVE-2023-1221",
    "CVE-2023-1222",
    "CVE-2023-1223",
    "CVE-2023-1224",
    "CVE-2023-1225",
    "CVE-2023-1226",
    "CVE-2023-1227",
    "CVE-2023-1228",
    "CVE-2023-1229",
    "CVE-2023-1230",
    "CVE-2023-1231",
    "CVE-2023-1232",
    "CVE-2023-1233",
    "CVE-2023-1234",
    "CVE-2023-1235",
    "CVE-2023-1236"
  );
  script_xref(name:"IAVA", value:"2023-A-0131-S");

  script_name(english:"Debian DSA-5371-1 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5371 advisory.

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

  - Stack buffer overflow in Crash reporting in Google Chrome on Windows prior to 111.0.5563.64 allowed a
    remote attacker who had compromised the renderer process to obtain potentially sensitive information from
    process memory via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1217)

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

  - Insufficient policy enforcement in Autofill in Google Chrome on Android prior to 111.0.5563.64 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1223)

  - Insufficient policy enforcement in Web Payments API in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1224)

  - Insufficient policy enforcement in Navigation in Google Chrome on iOS prior to 111.0.5563.64 allowed a
    remote attacker to bypass same origin policy via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1225)

  - Insufficient policy enforcement in Web Payments API in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to bypass content security policy via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1226)

  - Use after free in Core in Google Chrome on Lacros prior to 111.0.5563.64 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via crafted
    UI interaction. (Chromium security severity: Medium) (CVE-2023-1227)

  - Insufficient policy enforcement in Intents in Google Chrome on Android prior to 111.0.5563.64 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1228)

  - Inappropriate implementation in Permission prompts in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1229)

  - Inappropriate implementation in WebApp Installs in Google Chrome on Android prior to 111.0.5563.64 allowed
    an attacker who convinced a user to install a malicious WebApp to spoof the contents of the PWA installer
    via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-1230)

  - Inappropriate implementation in Autofill in Google Chrome on Android prior to 111.0.5563.64 allowed a
    remote attacker to potentially spoof the contents of the omnibox via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-1231)

  - Insufficient policy enforcement in Resource Timing in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to obtain potentially sensitive information from API via a crafted HTML page. (Chromium
    security severity: Low) (CVE-2023-1232)

  - Insufficient policy enforcement in Resource Timing in Google Chrome prior to 111.0.5563.64 allowed an
    attacker who convinced a user to install a malicious extension to obtain potentially sensitive information
    from API via a crafted Chrome Extension. (Chromium security severity: Low) (CVE-2023-1233)

  - Inappropriate implementation in Intents in Google Chrome on Android prior to 111.0.5563.64 allowed a
    remote attacker to perform domain spoofing via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-1234)

  - Type confusion in DevTools in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted UI interaction.
    (Chromium security severity: Low) (CVE-2023-1235)

  - Inappropriate implementation in Internals in Google Chrome prior to 111.0.5563.64 allowed a remote
    attacker to spoof the origin of an iframe via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-1236)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5371");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1213");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1214");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1215");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1216");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1217");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1219");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1220");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1221");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1222");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1223");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1224");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1225");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1226");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1227");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1228");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1229");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1230");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1231");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1232");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1233");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1234");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1235");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1236");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.

For the stable distribution (bullseye), these problems have been fixed in version 111.0.5563.64-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1227");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/10");

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
    {'release': '11.0', 'prefix': 'chromium', 'reference': '111.0.5563.64-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-common', 'reference': '111.0.5563.64-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-driver', 'reference': '111.0.5563.64-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-l10n', 'reference': '111.0.5563.64-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-sandbox', 'reference': '111.0.5563.64-1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-shell', 'reference': '111.0.5563.64-1~deb11u1'}
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
