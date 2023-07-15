#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-10.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(175034);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id(
    "CVE-2022-3445",
    "CVE-2022-3446",
    "CVE-2022-3447",
    "CVE-2022-3448",
    "CVE-2022-3449",
    "CVE-2022-3450",
    "CVE-2022-3723",
    "CVE-2022-4135",
    "CVE-2022-4174",
    "CVE-2022-4175",
    "CVE-2022-4176",
    "CVE-2022-4177",
    "CVE-2022-4178",
    "CVE-2022-4179",
    "CVE-2022-4180",
    "CVE-2022-4181",
    "CVE-2022-4182",
    "CVE-2022-4183",
    "CVE-2022-4184",
    "CVE-2022-4185",
    "CVE-2022-4186",
    "CVE-2022-4187",
    "CVE-2022-4188",
    "CVE-2022-4189",
    "CVE-2022-4190",
    "CVE-2022-4191",
    "CVE-2022-4192",
    "CVE-2022-4193",
    "CVE-2022-4194",
    "CVE-2022-4195",
    "CVE-2022-4436",
    "CVE-2022-4437",
    "CVE-2022-4438",
    "CVE-2022-4439",
    "CVE-2022-4440",
    "CVE-2022-41115",
    "CVE-2022-44688",
    "CVE-2022-44708",
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
    "CVE-2023-0141",
    "CVE-2023-21719",
    "CVE-2023-21775",
    "CVE-2023-21795",
    "CVE-2023-21796"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/12/19");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/11/18");

  script_name(english:"GLSA-202305-10 : Chromium, Google Chrome, Microsoft Edge: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-10 (Chromium, Google Chrome, Microsoft Edge:
Multiple Vulnerabilities)

  - Use after free in Skia in Google Chrome prior to 106.0.5249.119 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3445)

  - Heap buffer overflow in WebSQL in Google Chrome prior to 106.0.5249.119 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3446)

  - Inappropriate implementation in Custom Tabs in Google Chrome on Android prior to 106.0.5249.119 allowed a
    remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security
    severity: High) (CVE-2022-3447)

  - Use after free in Permissions API in Google Chrome prior to 106.0.5249.119 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: High) (CVE-2022-3448)

  - Use after free in Safe Browsing in Google Chrome prior to 106.0.5249.119 allowed an attacker who convinced
    a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome
    Extension. (Chromium security severity: High) (CVE-2022-3449)

  - Use after free in Peer Connection in Google Chrome prior to 106.0.5249.119 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3450)

  - Type confusion in V8 in Google Chrome prior to 107.0.5304.87 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3723)

  - Heap buffer overflow in GPU in Google Chrome prior to 107.0.5304.121 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (Chromium security severity: High) (CVE-2022-4135)

  - Type confusion in V8 in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4174)

  - Use after free in Camera Capture in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4175)

  - Out of bounds write in Lacros Graphics in Google Chrome on Chrome OS and Lacros prior to 108.0.5359.71
    allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially
    exploit heap corruption via UI interactions. (Chromium security severity: High) (CVE-2022-4176)

  - Use after free in Extensions in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a
    user to install an extension to potentially exploit heap corruption via a crafted Chrome Extension and UI
    interaction. (Chromium security severity: High) (CVE-2022-4177)

  - Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2022-4178)

  - Use after free in Audio in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user
    to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: High) (CVE-2022-4179)

  - Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user to
    install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: High) (CVE-2022-4180)

  - Use after free in Forms in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4181)

  - Inappropriate implementation in Fenced Frames in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass fenced frame restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4182)

  - Insufficient policy enforcement in Popup Blocker in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4183)

  - Insufficient policy enforcement in Autofill in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass autofill restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4184)

  - Inappropriate implementation in Navigation in Google Chrome on iOS prior to 108.0.5359.71 allowed a remote
    attacker to spoof the contents of the modal dialogue via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4185)

  - Insufficient validation of untrusted input in Downloads in Google Chrome prior to 108.0.5359.71 allowed an
    attacker who convinced a user to install a malicious extension to bypass Downloads restrictions via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2022-4186)

  - Insufficient policy enforcement in DevTools in Google Chrome on Windows prior to 108.0.5359.71 allowed a
    remote attacker to bypass filesystem restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4187)

  - Insufficient validation of untrusted input in CORS in Google Chrome on Android prior to 108.0.5359.71
    allowed a remote attacker to bypass same origin policy via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2022-4188)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 108.0.5359.71 allowed an attacker
    who convinced a user to install a malicious extension to bypass navigation restrictions via a crafted
    Chrome Extension. (Chromium security severity: Medium) (CVE-2022-4189)

  - Insufficient data validation in Directory in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4190)

  - Use after free in Sign-In in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who convinced
    a user to engage in specific UI interaction to potentially exploit heap corruption via profile
    destruction. (Chromium security severity: Medium) (CVE-2022-4191)

  - Use after free in Live Caption in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via UI
    interaction. (Chromium security severity: Medium) (CVE-2022-4192)

  - Insufficient policy enforcement in File System API in Google Chrome prior to 108.0.5359.71 allowed a
    remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4193)

  - Use after free in Accessibility in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4194)

  - Insufficient policy enforcement in Safe Browsing in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass Safe Browsing warnings via a malicious file. (Chromium security severity: Medium)
    (CVE-2022-4195)

  - Use after free in Blink Media in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4436)

  - Use after free in Mojo IPC in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4437)

  - Use after free in Blink Frames in Google Chrome prior to 108.0.5359.124 allowed a remote attacker who
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: High) (CVE-2022-4438)

  - Use after free in Aura in Google Chrome on Windows prior to 108.0.5359.124 allowed a remote attacker who
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via
    specific UI interactions. (Chromium security severity: High) (CVE-2022-4439)

  - Use after free in Profiles in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4440)

  - Microsoft Edge (Chromium-based) Update Elevation of Privilege Vulnerability. (CVE-2022-41115)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2022-44688)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. (CVE-2022-44708)

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

  - Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability. (CVE-2023-21719)

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability (CVE-2023-21775)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability (CVE-2023-21795, CVE-2023-21796)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-10");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=876855");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=878825");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=883031");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=883697");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=885851");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=886479");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=890726");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=890728");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=891501");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=891503");
  script_set_attribute(attribute:"solution", value:
"All Chromium users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-109.0.5414.74-r1
        
All Chromium binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-bin-109.0.5414.74
        
All Google Chrome users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/google-chrome-109.0.5414.74
        
All Microsoft Edge users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/microsoft-edge-109.0.1518.61");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0135");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-4135");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:microsoft-edge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'www-client/chromium',
    'unaffected' : make_list("ge 109.0.5414.74-r1"),
    'vulnerable' : make_list("lt 109.0.5414.74-r1")
  },
  {
    'name' : 'www-client/chromium-bin',
    'unaffected' : make_list("ge 109.0.5414.74"),
    'vulnerable' : make_list("lt 109.0.5414.74")
  },
  {
    'name' : 'www-client/google-chrome',
    'unaffected' : make_list("ge 109.0.5414.74"),
    'vulnerable' : make_list("lt 109.0.5414.74")
  },
  {
    'name' : 'www-client/microsoft-edge',
    'unaffected' : make_list("ge 109.0.1518.61"),
    'vulnerable' : make_list("lt 109.0.1518.61")
  }
];

foreach var package( packages ) {
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
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Chromium / Google Chrome / Microsoft Edge');
}
