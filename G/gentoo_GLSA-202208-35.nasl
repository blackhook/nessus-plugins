#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-35.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164320);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/29");

  script_cve_id(
    "CVE-2022-2163",
    "CVE-2022-2294",
    "CVE-2022-2295",
    "CVE-2022-2296",
    "CVE-2022-2477",
    "CVE-2022-2478",
    "CVE-2022-2479",
    "CVE-2022-2480",
    "CVE-2022-2481",
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
    "CVE-2022-33636",
    "CVE-2022-33649",
    "CVE-2022-35796"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/08");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"GLSA-202208-35 : Chromium, Google Chrome, Microsoft Edge: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-35 (Chromium, Google Chrome, Microsoft Edge:
Multiple Vulnerabilities)

  - Use after free in Cast UI and Toolbar in Google Chrome prior to 103.0.5060.134 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via UI
    interaction. (CVE-2022-2163)

  - Heap buffer overflow in WebRTC in Google Chrome prior to 103.0.5060.114 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2294)

  - Type confusion in V8 in Google Chrome prior to 103.0.5060.114 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2295)

  - Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 103.0.5060.114 allowed a remote
    attacker who convinced a user to engage in specific user interactions to potentially exploit heap
    corruption via direct UI interactions. (CVE-2022-2296)

  - Use after free in Guest View in Google Chrome prior to 103.0.5060.134 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-2477)

  - Use after free in PDF in Google Chrome prior to 103.0.5060.134 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2478)

  - Insufficient validation of untrusted input in File in Google Chrome on Android prior to 103.0.5060.134
    allowed an attacker who convinced a user to install a malicious app to obtain potentially sensitive
    information from internal file directories via a crafted HTML page. (CVE-2022-2479)

  - Use after free in Service Worker API in Google Chrome prior to 103.0.5060.134 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2480)

  - Use after free in Views in Google Chrome prior to 103.0.5060.134 allowed a remote attacker who convinced a
    user to engage in specific user interactions to potentially exploit heap corruption via UI interaction.
    (CVE-2022-2481)

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

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability. (CVE-2022-33636)

  - Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability. (CVE-2022-33649)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. (CVE-2022-35796)

  - Use after free in FedCM. (CVE-2022-2852)

  - Heap buffer overflow in Downloads. (CVE-2022-2853)

  - Use after free in SwiftShader. (CVE-2022-2854)

  - Use after free in ANGLE. (CVE-2022-2855)

  - Insufficient validation of untrusted input in Intents. (CVE-2022-2856)

  - Use after free in Blink. (CVE-2022-2857)

  - Use after free in Sign-In Flow. (CVE-2022-2858)

  - Use after free in Chrome OS Shell. (CVE-2022-2859)

  - Insufficient policy enforcement in Cookies. (CVE-2022-2860)

  - Inappropriate implementation in Extensions API. (CVE-2022-2861)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-35");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=858104");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=859442");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=863512");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=864723");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=865501");
  script_set_attribute(attribute:"solution", value:
"All Chromium users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-104.0.5112.101
        
All Chromium binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-bin-104.0.5112.101
        
All Google Chrome users should upgrade to tha latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/google-chrome-104.0.5112.101
        
All Microsoft Edge users should upgrade to tha latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/microsoft-edge-104.0.1293.63");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2859");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-33649");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:microsoft-edge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'unaffected' : make_list("ge 104.0.5112.101"),
    'vulnerable' : make_list("lt 104.0.5112.101")
  },
  {
    'name' : "www-client/chromium-bin",
    'unaffected' : make_list("ge 104.0.5112.101"),
    'vulnerable' : make_list("lt 104.0.5112.101")
  },
  {
    'name' : "www-client/google-chrome",
    'unaffected' : make_list("ge 104.0.5112.101"),
    'vulnerable' : make_list("lt 104.0.5112.101")
  },
  {
    'name' : "www-client/microsoft-edge",
    'unaffected' : make_list("ge 104.0.1293.63"),
    'vulnerable' : make_list("lt 104.0.1293.63")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


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
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / Google Chrome / Microsoft Edge");
}
