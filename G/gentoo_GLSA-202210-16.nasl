#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-16.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166728);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/31");

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
    "CVE-2022-3318",
    "CVE-2022-3370",
    "CVE-2022-3373",
    "CVE-2022-3445",
    "CVE-2022-3446",
    "CVE-2022-3447",
    "CVE-2022-3448",
    "CVE-2022-3449",
    "CVE-2022-3450",
    "CVE-2022-41035"
  );

  script_name(english:"GLSA-202210-16 : Chromium, Google Chrome, Microsoft Edge: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-16 (Chromium, Google Chrome, Microsoft Edge:
Multiple Vulnerabilities)

  - Insufficient validation of untrusted input in DevTools in Google Chrome on Chrome OS prior to
    105.0.5195.125 allowed an attacker who convinced a user to install a malicious extension to bypass
    navigation restrictions via a crafted HTML page. (CVE-2022-3201)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability. (CVE-2022-41035)

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

  - This CVE was assigned by Chrome. Microsoft Edge (Chromium-based) ingests Chromium, which addresses this
    vulnerability. Please see Google Chrome Releases for more information. (CVE-2022-3315, CVE-2022-3316,
    CVE-2022-3370, CVE-2022-3373)

  - Insufficient validation of untrusted input in Intents. (CVE-2022-3317)

  - Use after free in ChromeOS Notifications. (CVE-2022-3318)

  - Use after free in Skia. (CVE-2022-3445)

  - Heap buffer overflow in WebSQL. (CVE-2022-3446)

  - Inappropriate implementation in Custom Tabs. (CVE-2022-3447)

  - Use after free in Permissions API. (CVE-2022-3448)

  - Use after free in Safe Browsing. (CVE-2022-3449)

  - Use after free in Peer Connection. (CVE-2022-3450)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-16");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=873217");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=873817");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=874855");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=876855");
  script_set_attribute(attribute:"solution", value:
"All Chromium users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-106.0.5249.119
        
All Chromium binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-bin-106.0.5249.119
        
All Google Chrome users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/google-chrome-106.0.5249.119
        
All Microsoft Edge users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/microsoft-edge-106.0.1370.37");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3450");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41035");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/31");

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
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'www-client/chromium',
    'unaffected' : make_list("ge 106.0.5249.119", "lt 106.0.0"),
    'vulnerable' : make_list("lt 106.0.5249.119")
  },
  {
    'name' : 'www-client/chromium-bin',
    'unaffected' : make_list("ge 106.0.5249.119", "lt 106.0.0"),
    'vulnerable' : make_list("lt 106.0.5249.119")
  },
  {
    'name' : 'www-client/google-chrome',
    'unaffected' : make_list("ge 106.0.5249.119", "lt 106.0.0"),
    'vulnerable' : make_list("lt 106.0.5249.119")
  },
  {
    'name' : 'www-client/microsoft-edge',
    'unaffected' : make_list("ge 106.0.1370.37", "lt 106.0.0"),
    'vulnerable' : make_list("lt 106.0.1370.37")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Chromium / Google Chrome / Microsoft Edge');
}
