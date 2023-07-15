#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-3ca063941b
#

include('compat.inc');

if (description)
{
  script_id(169098);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2022-2007",
    "CVE-2022-2008",
    "CVE-2022-2010",
    "CVE-2022-2011",
    "CVE-2022-2603",
    "CVE-2022-2604",
    "CVE-2022-2605",
    "CVE-2022-2606",
    "CVE-2022-2607",
    "CVE-2022-2608",
    "CVE-2022-2609",
    "CVE-2022-2610",
    "CVE-2022-2611",
    "CVE-2022-2612",
    "CVE-2022-2613",
    "CVE-2022-2614",
    "CVE-2022-2615",
    "CVE-2022-2616",
    "CVE-2022-2617",
    "CVE-2022-2618",
    "CVE-2022-2619",
    "CVE-2022-2620",
    "CVE-2022-2621",
    "CVE-2022-2622",
    "CVE-2022-2623",
    "CVE-2022-2624",
    "CVE-2022-2852",
    "CVE-2022-2853",
    "CVE-2022-2854",
    "CVE-2022-2855",
    "CVE-2022-2856",
    "CVE-2022-2857",
    "CVE-2022-2858",
    "CVE-2022-2859",
    "CVE-2022-2860",
    "CVE-2022-2861",
    "CVE-2022-3038",
    "CVE-2022-3039",
    "CVE-2022-3040",
    "CVE-2022-3041",
    "CVE-2022-3042",
    "CVE-2022-3043",
    "CVE-2022-3044",
    "CVE-2022-3045",
    "CVE-2022-3046",
    "CVE-2022-3047",
    "CVE-2022-3048",
    "CVE-2022-3049",
    "CVE-2022-3050",
    "CVE-2022-3051",
    "CVE-2022-3052",
    "CVE-2022-3053",
    "CVE-2022-3054",
    "CVE-2022-3055",
    "CVE-2022-3056",
    "CVE-2022-3057",
    "CVE-2022-3058",
    "CVE-2022-3071",
    "CVE-2022-3075",
    "CVE-2022-3195",
    "CVE-2022-3196",
    "CVE-2022-3197",
    "CVE-2022-3198",
    "CVE-2022-3199",
    "CVE-2022-3200",
    "CVE-2022-3201"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/29");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/08");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");
  script_xref(name:"FEDORA", value:"2022-3ca063941b");

  script_name(english:"Fedora 35 : chromium (2022-3ca063941b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 35 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-3ca063941b advisory.

  - Use after free in WebGPU in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2007)

  - Double free in WebGL in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2008)

  - Out of bounds read in compositing in Google Chrome prior to 102.0.5005.115 allowed a remote attacker who
    had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2022-2010)

  - Use after free in ANGLE in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2011)

  - Use after free in Omnibox in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2603)

  - Use after free in Safe Browsing in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2604)

  - Out of bounds read in Dawn in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2605)

  - Use after free in Managed devices API in Google Chrome prior to 104.0.5112.79 allowed a remote attacker
    who convinced a user to enable a specific Enterprise policy to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-2606)

  - Use after free in Tab Strip in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker
    who convinced a user to engage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2607)

  - Use after free in Overview Mode in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote
    attacker who convinced a user to engage in specific user interactions to potentially exploit heap
    corruption via specific UI interactions. (CVE-2022-2608)

  - Use after free in Nearby Share in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote
    attacker who convinced a user to engage in specific user interactions to potentially exploit heap
    corruption via specific UI interactions. (CVE-2022-2609)

  - Insufficient policy enforcement in Background Fetch in Google Chrome prior to 104.0.5112.79 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-2610)

  - Inappropriate implementation in Fullscreen API in Google Chrome on Android prior to 104.0.5112.79 allowed
    a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-2611)

  - Side-channel information leakage in Keyboard input in Google Chrome prior to 104.0.5112.79 allowed a
    remote attacker who had compromised the renderer process to obtain potentially sensitive information from
    process memory via a crafted HTML page. (CVE-2022-2612)

  - Use after free in Input in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to enage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2613)

  - Use after free in Sign-In Flow in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2614)

  - Insufficient policy enforcement in Cookies in Google Chrome prior to 104.0.5112.79 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-2615)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 104.0.5112.79 allowed an attacker
    who convinced a user to install a malicious extension to spoof the contents of the Omnibox (URL bar) via a
    crafted Chrome Extension. (CVE-2022-2616)

  - Use after free in Extensions API in Google Chrome prior to 104.0.5112.79 allowed an attacker who convinced
    a user to install a malicious extension to potentially exploit heap corruption via specific UI
    interactions. (CVE-2022-2617)

  - Insufficient validation of untrusted input in Internals in Google Chrome prior to 104.0.5112.79 allowed a
    remote attacker to bypass download restrictions via a malicious file . (CVE-2022-2618)

  - Insufficient validation of untrusted input in Settings in Google Chrome prior to 104.0.5112.79 allowed an
    attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged
    page via a crafted HTML page. (CVE-2022-2619)

  - Use after free in WebUI in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2620)

  - Use after free in Extensions in Google Chrome prior to 104.0.5112.79 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific UI interactions.
    (CVE-2022-2621)

  - Insufficient validation of untrusted input in Safe Browsing in Google Chrome on Windows prior to
    104.0.5112.79 allowed a remote attacker to bypass download restrictions via a crafted file.
    (CVE-2022-2622)

  - Use after free in Offline in Google Chrome on Android prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2623)

  - Heap buffer overflow in PDF in Google Chrome prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via a
    crafted PDF file. (CVE-2022-2624)

  - Use after free in FedCM in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2852)

  - Heap buffer overflow in Downloads in Google Chrome on Android prior to 104.0.5112.101 allowed a remote
    attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted
    HTML page. (CVE-2022-2853)

  - Use after free in SwiftShader in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2854)

  - Use after free in ANGLE in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2855)

  - Insufficient validation of untrusted input in Intents in Google Chrome on Android prior to 104.0.5112.101
    allowed a remote attacker to arbitrarily browse to a malicious website via a crafted HTML page.
    (CVE-2022-2856)

  - Use after free in Blink in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2857)

  - Use after free in Sign-In Flow in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to
    potentially exploit heap corruption via specific UI interaction. (CVE-2022-2858)

  - Use after free in Chrome OS Shell in Google Chrome prior to 104.0.5112.101 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via specific
    UI interactions. (CVE-2022-2859)

  - Insufficient policy enforcement in Cookies in Google Chrome prior to 104.0.5112.101 allowed a remote
    attacker to bypass cookie prefix restrictions via a crafted HTML page. (CVE-2022-2860)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 104.0.5112.101 allowed an
    attacker who convinced a user to install a malicious extension to inject arbitrary scripts into WebUI via
    a crafted HTML page. (CVE-2022-2861)

  - Use after free in Network Service in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-3038)

  - Use after free in WebSQL in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-3039, CVE-2022-3041)

  - Use after free in Layout in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-3040)

  - Use after free in PhoneHub in Google Chrome on Chrome OS prior to 105.0.5195.52 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (CVE-2022-3042)

  - Heap buffer overflow in Screen Capture in Google Chrome on Chrome OS prior to 105.0.5195.52 allowed a
    remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap
    corruption via a crafted HTML page. (CVE-2022-3043)

  - Inappropriate implementation in Site Isolation in Google Chrome prior to 105.0.5195.52 allowed a remote
    attacker who had compromised the renderer process to bypass site isolation via a crafted HTML page.
    (CVE-2022-3044)

  - Insufficient validation of untrusted input in V8 in Google Chrome prior to 105.0.5195.52 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2022-3045)

  - Use after free in Browser Tag in Google Chrome prior to 105.0.5195.52 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-3046)

  - Insufficient policy enforcement in Extensions API in Google Chrome prior to 105.0.5195.52 allowed an
    attacker who convinced a user to install a malicious extension to bypass downloads policy via a crafted
    HTML page. (CVE-2022-3047)

  - Inappropriate implementation in Chrome OS lockscreen in Google Chrome on Chrome OS prior to 105.0.5195.52
    allowed a local attacker to bypass lockscreen navigation restrictions via physical access to the device.
    (CVE-2022-3048)

  - Use after free in SplitScreen in Google Chrome on Chrome OS, Lacros prior to 105.0.5195.52 allowed a
    remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap
    corruption via a crafted HTML page. (CVE-2022-3049)

  - Heap buffer overflow in WebUI in Google Chrome on Chrome OS prior to 105.0.5195.52 allowed a remote
    attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption
    via crafted UI interactions. (CVE-2022-3050)

  - Heap buffer overflow in Exosphere in Google Chrome on Chrome OS, Lacros prior to 105.0.5195.52 allowed a
    remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap
    corruption via crafted UI interactions. (CVE-2022-3051)

  - Heap buffer overflow in Window Manager in Google Chrome on Chrome OS, Lacros prior to 105.0.5195.52
    allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially
    exploit heap corruption via crafted UI interactions. (CVE-2022-3052)

  - Inappropriate implementation in Pointer Lock in Google Chrome on Mac prior to 105.0.5195.52 allowed a
    remote attacker to restrict user navigation via a crafted HTML page. (CVE-2022-3053)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 105.0.5195.52 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2022-3054)

  - Use after free in Passwords in Google Chrome prior to 105.0.5195.52 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-3055)

  - Insufficient policy enforcement in Content Security Policy in Google Chrome prior to 105.0.5195.52 allowed
    a remote attacker to bypass content security policy via a crafted HTML page. (CVE-2022-3056)

  - Inappropriate implementation in iframe Sandbox in Google Chrome prior to 105.0.5195.52 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-3057)

  - Use after free in Sign-In Flow in Google Chrome prior to 105.0.5195.52 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via crafted
    UI interaction. (CVE-2022-3058)

  - Use after free in Tab Strip in Google Chrome on Chrome OS, Lacros prior to 105.0.5195.52 allowed a remote
    attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption
    via crafted UI interaction. (CVE-2022-3071)

  - Insufficient data validation in Mojo in Google Chrome prior to 105.0.5195.102 allowed a remote attacker
    who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2022-3075)

  - Out of bounds write in Storage in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to
    perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3195)

  - Use after free in PDF in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (Chromium security severity: High) (CVE-2022-3196,
    CVE-2022-3197, CVE-2022-3198)

  - Use after free in Frames in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3199)

  - Heap buffer overflow in Internals in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3200)

  - Insufficient validation of untrusted input in DevTools in Google Chrome on Chrome OS prior to
    105.0.5195.125 allowed an attacker who convinced a user to install a malicious extension to bypass
    navigation restrictions via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3201)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-3ca063941b");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3199");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3075");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^35([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 35', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'chromium-105.0.5195.125-2.fc35', 'release':'FC35', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium');
}
