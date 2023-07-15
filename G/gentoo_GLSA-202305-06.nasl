#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-06.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(175044);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id(
    "CVE-2022-46871",
    "CVE-2022-46872",
    "CVE-2022-46873",
    "CVE-2022-46874",
    "CVE-2022-46875",
    "CVE-2022-46877",
    "CVE-2022-46878",
    "CVE-2022-46879",
    "CVE-2022-46880",
    "CVE-2022-46881",
    "CVE-2022-46882",
    "CVE-2023-23597",
    "CVE-2023-23598",
    "CVE-2023-23599",
    "CVE-2023-23600",
    "CVE-2023-23601",
    "CVE-2023-23602",
    "CVE-2023-23603",
    "CVE-2023-23604",
    "CVE-2023-23605",
    "CVE-2023-23606"
  );

  script_name(english:"GLSA-202305-06 : Mozilla Firefox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-06 (Mozilla Firefox: Multiple Vulnerabilities)

  - An out of date library (libusrsctp) contained vulnerabilities that could potentially be exploited. This
    vulnerability affects Firefox < 108. (CVE-2022-46871)

  - An attacker who compromised a content process could have partially escaped the sandbox to read arbitrary
    files via clipboard-related IPC messages.<br>*This bug only affects Thunderbird for Linux. Other operating
    systems are unaffected.*. This vulnerability affects Firefox < 108, Firefox ESR < 102.6, and Thunderbird <
    102.6. (CVE-2022-46872)

  - Because Firefox did not implement the <code>unsafe-hashes</code> CSP directive, an attacker who was able
    to inject markup into a page otherwise protected by a Content Security Policy may have been able to inject
    executable script. This would be severely constrained by the specified Content Security Policy of the
    document. This vulnerability affects Firefox < 108. (CVE-2022-46873)

  - A file with a long filename could have had its filename truncated to remove the valid extension, leaving a
    malicious extension in its place. This could potentially led to user confusion and the execution of
    malicious code.<br/>*Note*: This issue was originally included in the advisories for Thunderbird 102.6,
    but a patch (specific to Thunderbird) was omitted, resulting in it actually being fixed in Thunderbird
    102.6.1. This vulnerability affects Firefox < 108, Thunderbird < 102.6.1, Thunderbird < 102.6, and Firefox
    ESR < 102.6. (CVE-2022-46874)

  - The executable file warning was not presented when downloading .atloc and .ftploc files, which can run
    commands on a user's computer. <br>*Note: This issue only affected Mac OS operating systems. Other
    operating systems are unaffected.*. This vulnerability affects Firefox < 108, Firefox ESR < 102.6, and
    Thunderbird < 102.6. (CVE-2022-46875)

  - By confusing the browser, the fullscreen notification could have been delayed or suppressed, resulting in
    potential user confusion or spoofing attacks. This vulnerability affects Firefox < 108. (CVE-2022-46877)

  - Mozilla developers Randell Jesup, Valentin Gosu, Olli Pettay, and the Mozilla Fuzzing Team reported memory
    safety bugs present in Thunderbird 102.5. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 108, Firefox ESR < 102.6, and Thunderbird < 102.6. (CVE-2022-46878)

  - Mozilla developers and community members Lukas Bernhard, Gabriele Svelto, Randell Jesup, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Firefox 107. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 108. (CVE-2022-46879)

  - A missing check related to tex units could have led to a use-after-free and potentially exploitable
    crash.<br />*Note*: This advisory was added on December 13th, 2022 after we better understood the impact
    of the issue. The fix was included in the original release of Firefox 105. This vulnerability affects
    Firefox ESR < 102.6, Firefox < 105, and Thunderbird < 102.6. (CVE-2022-46880)

  - An optimization in WebGL was incorrect in some cases, and could have led to memory corruption and a
    potentially exploitable crash. This vulnerability affects Firefox < 106, Firefox ESR < 102.6, and
    Thunderbird < 102.6. (CVE-2022-46881)

  - A use-after-free in WebGL extensions could have led to a potentially exploitable crash. This vulnerability
    affects Firefox < 107, Firefox ESR < 102.6, and Thunderbird < 102.6. (CVE-2022-46882)

  - A compromised web child process could disable web security opening restrictions, leading to a new child
    process being spawned within the <code>file://</code> context. Given a reliable exploit primitive, this
    new process could be exploited again leading to arbitrary file read.  (CVE-2023-23597)

  - Mozilla: Arbitrary file read from GTK drag and drop on Linux (CVE-2023-23598)

  - Mozilla: Malicious command could be hidden in devtools output (CVE-2023-23599)

  - Per origin notification permissions were being stored in a way that didn't take into account what browsing
    context the permission was granted in. This lead to the possibility of notifications to be displayed
    during different browsing sessions. This bug only affects Firefox for Android. Other operating systems are
    unaffected.  (CVE-2023-23600)

  - Mozilla: URL being dragged from cross-origin iframe into same tab triggers navigation (CVE-2023-23601)

  - Mozilla: Content Security Policy wasn't being correctly applied to WebSockets in WebWorkers
    (CVE-2023-23602)

  - Mozilla: Calls to <code>console.log</code> allowed bypasing Content Security Policy via format directive
    (CVE-2023-23603)

  - A duplicate <code>SystemPrincipal</code> object could be created when parsing a non-system html document
    via <code>DOMParser::ParseFromSafeString</code>. This could have lead to bypassing web security checks.
    (CVE-2023-23604)

  - Mozilla: Memory safety bugs fixed in Firefox 109 and Firefox ESR 102.7 (CVE-2023-23605)

  - Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 108. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code.  (CVE-2023-23606)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-06");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=885813");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=891213");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Firefox ESR binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-102.7.0:esr
        
All Mozilla Firefox ESR users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-102.7.0:esr
        
All Mozilla Firefox binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-109.0:rapid
        
All Mozilla Firefox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-109.0:rapid");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
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
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 102.7.0", "lt 102.0.0"),
    'vulnerable' : make_list("lt 102.7.0")
  },
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 109.0", "lt 103.0.0"),
    'vulnerable' : make_list("lt 109.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 102.7.0", "lt 102.0.0"),
    'vulnerable' : make_list("lt 102.7.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 109.0", "lt 103.0.0"),
    'vulnerable' : make_list("lt 109.0")
  }
];

foreach var package( packages ) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mozilla Firefox');
}
