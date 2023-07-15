#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202209-23.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(165535);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
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
    "CVE-2022-3201",
    "CVE-2022-38012"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/29");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");
  script_xref(name:"IAVA", value:"2022-A-0388-S");
  script_xref(name:"IAVA", value:"2022-A-0394-S");
  script_xref(name:"IAVA", value:"2022-A-0396-S");

  script_name(english:"GLSA-202209-23 : Chromium, Google Chrome, Microsoft Edge: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202209-23 (Chromium, Google Chrome, Microsoft Edge:
Multiple Vulnerabilities)

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
    perform an out of bounds memory write via a crafted HTML page. (CVE-2022-3195)

  - Use after free in PDF in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (CVE-2022-3196, CVE-2022-3197, CVE-2022-3198)

  - Use after free in Frames in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-3199)

  - Heap buffer overflow in Internals in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-3200)

  - Insufficient validation of untrusted input in DevTools in Google Chrome on Chrome OS prior to
    105.0.5195.125 allowed an attacker who convinced a user to install a malicious extension to bypass
    navigation restrictions via a crafted HTML page. (CVE-2022-3201)

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability. (CVE-2022-38012)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202209-23");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=868156");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=868354");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=870142");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=872407");
  script_set_attribute(attribute:"solution", value:
"All Chromium users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-105.0.5195.125
        
All Chromium binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-bin-105.0.5195.125
        
All Google Chrome users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/google-chrome-105.0.5195.125
        
All Microsoft Edge users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/microsoft-edge-105.0.1343.42");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3199");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3200");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:microsoft-edge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "www-client/chromium",
    'unaffected' : make_list("ge 105.0.5195.125", "lt 105.0.0"),
    'vulnerable' : make_list("lt 105.0.5195.125")
  },
  {
    'name' : "www-client/chromium-bin",
    'unaffected' : make_list("ge 105.0.5195.125", "lt 105.0.0"),
    'vulnerable' : make_list("lt 105.0.5195.125")
  },
  {
    'name' : "www-client/google-chrome",
    'unaffected' : make_list("ge 105.0.5195.125", "lt 105.0.0"),
    'vulnerable' : make_list("lt 105.0.5195.125")
  },
  {
    'name' : "www-client/microsoft-edge",
    'unaffected' : make_list("ge 105.0.1343.42", "lt 105.0.0"),
    'vulnerable' : make_list("lt 105.0.1343.42")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / Google Chrome / Microsoft Edge");
}
