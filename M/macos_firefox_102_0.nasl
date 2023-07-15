## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-24.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(162603);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/02");

  script_cve_id(
    "CVE-2022-2200",
    "CVE-2022-34468",
    "CVE-2022-34469",
    "CVE-2022-34470",
    "CVE-2022-34471",
    "CVE-2022-34472",
    "CVE-2022-34473",
    "CVE-2022-34474",
    "CVE-2022-34475",
    "CVE-2022-34476",
    "CVE-2022-34477",
    "CVE-2022-34478",
    "CVE-2022-34479",
    "CVE-2022-34480",
    "CVE-2022-34481",
    "CVE-2022-34482",
    "CVE-2022-34483",
    "CVE-2022-34484",
    "CVE-2022-34485"
  );
  script_xref(name:"IAVA", value:"2022-A-2056-S");
  script_xref(name:"IAVA", value:"2022-A-0256-S");

  script_name(english:"Mozilla Firefox < 102.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 102.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2022-24 advisory.

  - A malicious website that could create a popup could have resized the popup to overlay the address bar with
    its own content, resulting in potential user confusion or spoofing attacks.   This bug only affects
    Firefox for Linux. Other operating systems are unaffected. (CVE-2022-34479)

  - Navigations between XML documents may have led to a use-after-free and potentially exploitable crash.
    (CVE-2022-34470)

  - An iframe that was not permitted to run scripts could do so if the user clicked on a
    <code>javascript:</code> link. (CVE-2022-34468)

  - An attacker who could have convinced a user to drag and drop an image to a filesystem could have
    manipulated the resulting filename to contain an executable extension, and by extension potentially
    tricked the user into executing malicious code.  While very similar, this is a separate issue from
    CVE-2022-34483. (CVE-2022-34482)

  - An attacker who could have convinced a user to drag and drop an image to a filesystem could have
    manipulated the resulting filename to contain an executable extension, and by extension potentially
    tricked the user into executing malicious code.  While very similar, this is a separate issue from
    CVE-2022-34482. (CVE-2022-34483)

  - ASN.1 parsing of an indefinite SEQUENCE inside an indefinite GROUP could have resulted in the parser
    accepting malformed ASN.1. (CVE-2022-34476)

  - In the <code>nsTArrayImpl::ReplaceElementsAt()</code> function, an integer overflow could have occurred
    when the number of elements to replace was too large for the container. (CVE-2022-34481)

  - Even when an iframe was sandboxed with <code>allow-top-navigation-by-user-activation</code>, if it
    received a redirect header to an external protocol the browser would process the redirect and prompt the
    user as appropriate. (CVE-2022-34474)

  - When a TLS Certificate error occurs on a domain protected by the HSTS header, the browser should not allow
    the user to bypass the certificate error.  On Firefox for Android, the user was presented with the option
    to bypass the error; this could only have been done by the user explicitly.  This bug only affects Firefox
    for Android. Other operating systems are unaffected. (CVE-2022-34469)

  - When downloading an update for an addon, the downloaded addon update's version was not verified to match
    the version selected from the manifest.  If the manifest had been tampered with on the server, an attacker
    could trick the browser into downgrading the addon to a prior version. (CVE-2022-34471)

  - If there was a PAC URL set and the server that hosts the PAC was not reachable, OCSP requests would have
    been blocked, resulting in incorrect error pages being shown. (CVE-2022-34472)

  - The <code>ms-msdt</code>, <code>search</code>, and <code>search-ms</code> protocols deliver content to
    Microsoft applications, bypassing the browser, when a user accepts a prompt. These applications have had
    known vulnerabilities, exploited in the wild (although we know of none exploited through Firefox), so in
    this release Firefox has blocked these protocols from prompting the user to open them. This bug only
    affects Firefox on Windows. Other operating systems are unaffected. (CVE-2022-34478)

  - If an object prototype was corrupted by an attacker, they would have been able to set undesired attributes
    on a JavaScript object, leading to privileged code execution. (CVE-2022-2200)

  - Within the <code>lginit()</code> function, if several allocations succeed but then one fails, an
    uninitialized pointer would have been freed despite never being allocated. (CVE-2022-34480)

  - The MediaError message property should be consistent to avoid leaking information about cross-origin
    resources; however for a same-site cross-origin resource, the message could have leaked information
    enabling XS-Leaks attacks. (CVE-2022-34477)

  - SVG <code><use></code> tags that referenced a same-origin document could have resulted in script
    execution if attacker input was sanitized via the HTML Sanitizer API. This would have required the
    attacker to reference a same-origin JavaScript file containing the script to be executed. (CVE-2022-34475)

  - The HTML Sanitizer should have sanitized the <code>href</code> attribute of SVG <code><use></code>
    tags; however it incorrectly did not sanitize <code>xlink:href</code> attributes. (CVE-2022-34473)

  - The Mozilla Fuzzing Team reported potential vulnerabilities present in Firefox 101 and Firefox ESR 91.10.
    Some of these bugs showed evidence of JavaScript prototype or memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. (CVE-2022-34484)

  - Mozilla developers Bryce Seager van Dyk and the Mozilla Fuzzing Team reported potential vulnerabilities
    present in Firefox 101. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. (CVE-2022-34485)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-24/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 102.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'102.0', severity:SECURITY_HOLE);
