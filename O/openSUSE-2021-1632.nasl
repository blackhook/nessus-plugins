#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1632-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156341);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-4052",
    "CVE-2021-4053",
    "CVE-2021-4054",
    "CVE-2021-4055",
    "CVE-2021-4056",
    "CVE-2021-4057",
    "CVE-2021-4058",
    "CVE-2021-4059",
    "CVE-2021-4061",
    "CVE-2021-4062",
    "CVE-2021-4063",
    "CVE-2021-4064",
    "CVE-2021-4065",
    "CVE-2021-4066",
    "CVE-2021-4067",
    "CVE-2021-4068",
    "CVE-2021-4078",
    "CVE-2021-4079",
    "CVE-2021-4098",
    "CVE-2021-4099",
    "CVE-2021-4100",
    "CVE-2021-4101",
    "CVE-2021-4102",
    "CVE-2021-38005",
    "CVE-2021-38006",
    "CVE-2021-38007",
    "CVE-2021-38008",
    "CVE-2021-38009",
    "CVE-2021-38010",
    "CVE-2021-38011",
    "CVE-2021-38012",
    "CVE-2021-38013",
    "CVE-2021-38014",
    "CVE-2021-38015",
    "CVE-2021-38016",
    "CVE-2021-38017",
    "CVE-2021-38018",
    "CVE-2021-38019",
    "CVE-2021-38020",
    "CVE-2021-38021",
    "CVE-2021-38022"
  );
  script_xref(name:"IAVA", value:"2021-A-0568-S");
  script_xref(name:"IAVA", value:"2021-A-0576-S");
  script_xref(name:"IAVA", value:"2021-A-0555-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/29");

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2021:1632-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1632-1 advisory.

  - Use after free in loader in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38005)

  - Use after free in storage foundation in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38006, CVE-2021-38011)

  - Type confusion in V8 in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38007, CVE-2021-38012)

  - Use after free in media in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38008)

  - Inappropriate implementation in cache in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (CVE-2021-38009)

  - Inappropriate implementation in service workers in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker who had compromised the renderer process to bypass site isolation via a crafted HTML page.
    (CVE-2021-38010)

  - Heap buffer overflow in fingerprint recognition in Google Chrome on ChromeOS prior to 96.0.4664.45 allowed
    a remote attacker who had compromised a WebUI renderer process to potentially perform a sandbox escape via
    a crafted HTML page. (CVE-2021-38013)

  - Out of bounds write in Swiftshader in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38014)

  - Inappropriate implementation in input in Google Chrome prior to 96.0.4664.45 allowed an attacker who
    convinced a user to install a malicious extension to bypass navigation restrictions via a crafted Chrome
    Extension. (CVE-2021-38015)

  - Insufficient policy enforcement in background fetch in Google Chrome prior to 96.0.4664.45 allowed a
    remote attacker to bypass same origin policy via a crafted HTML page. (CVE-2021-38016)

  - Insufficient policy enforcement in iframe sandbox in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2021-38017)

  - Inappropriate implementation in navigation in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker to perform domain spoofing via a crafted HTML page. (CVE-2021-38018)

  - Insufficient policy enforcement in CORS in Google Chrome prior to 96.0.4664.45 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (CVE-2021-38019)

  - Insufficient policy enforcement in contacts picker in Google Chrome on Android prior to 96.0.4664.45
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (CVE-2021-38020)

  - Inappropriate implementation in referrer in Google Chrome prior to 96.0.4664.45 allowed a remote attacker
    to bypass navigation restrictions via a crafted HTML page. (CVE-2021-38021)

  - Inappropriate implementation in WebAuthentication in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-38022)

  - Use after free in web apps in Google Chrome prior to 96.0.4664.93 allowed an attacker who convinced a user
    to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (CVE-2021-4052)

  - Use after free in UI in Google Chrome on Linux prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4053)

  - Incorrect security UI in autofill in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    perform domain spoofing via a crafted HTML page. (CVE-2021-4054)

  - Heap buffer overflow in extensions in Google Chrome prior to 96.0.4664.93 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    Chrome Extension. (CVE-2021-4055)

  - Type confusion in loader in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-4056)

  - Use after free in file API in Google Chrome prior to 96.0.4664.93 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-4057)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4058)

  - Insufficient data validation in loader in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (CVE-2021-4059)

  - Type confusion in V8 in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-4061, CVE-2021-4078)

  - Heap buffer overflow in BFCache in Google Chrome prior to 96.0.4664.93 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-4062)

  - Use after free in developer tools in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4063)

  - Use after free in screen capture in Google Chrome on ChromeOS prior to 96.0.4664.93 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4064)

  - Use after free in autofill in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-4065)

  - Integer underflow in ANGLE in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-4066)

  - Use after free in window manager in Google Chrome on ChromeOS prior to 96.0.4664.93 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4067)

  - Insufficient data validation in new tab page in Google Chrome prior to 96.0.4664.93 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-4068)

  - Out of bounds write in WebRTC in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via crafted WebRTC packets. (CVE-2021-4079)

  - Insufficient data validation in Mojo. (CVE-2021-4098)

  - Use after free in Swiftshader. (CVE-2021-4099)

  - Object lifecycle issue in ANGLE. (CVE-2021-4100)

  - Heap buffer overflow in Swiftshader. (CVE-2021-4101)

  - Use after free in V8. (CVE-2021-4102)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193713");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DUJZLITO4GTLR5FP75FBCLDYZMUY2AFI/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbea4788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38018");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38022");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4100");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4102");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4102");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-38013");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-96.0.4664.110-lp152.2.143.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-96.0.4664.110-lp152.2.143.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium');
}
