## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-07.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(146779);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2021-23968",
    "CVE-2021-23969",
    "CVE-2021-23970",
    "CVE-2021-23971",
    "CVE-2021-23972",
    "CVE-2021-23973",
    "CVE-2021-23974",
    "CVE-2021-23975",
    "CVE-2021-23976",
    "CVE-2021-23977",
    "CVE-2021-23978",
    "CVE-2021-23979"
  );
  script_xref(name:"IAVA", value:"2021-A-0107-S");

  script_name(english:"Mozilla Firefox < 86.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 86.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2021-07 advisory.

  - As specified in the W3C Content Security Policy draft, when creating a violation report, User agents need
    to ensure that the source file is the URL requested by the page, pre-redirects. If thats not possible,
    user agents need to strip the URL down to an origin to avoid unintentional leakage. Under certain types
    of redirects, Firefox incorrectly set the source file to be the destination of the redirects. This was
    fixed to be the redirect destination's origin. (CVE-2021-23969)

  - Context-specific code was included in a shared jump table; resulting in assertions being triggered in
    multithreaded wasm code. (CVE-2021-23970)

  - If Content Security Policy blocked frame navigation, the full destination of a redirect served in the
    frame was reported in the violation report; as opposed to the original frame URI. This could be used to
    leak sensitive information contained in such URIs. (CVE-2021-23968)

  - The DOMParser API did not properly process <noscript> elements for escaping. This could
    be used as an mXSS vector to bypass an HTML Sanitizer. (CVE-2021-23974)

  - When processing a redirect with a conflicting Referrer-Policy, Firefox would have adopted the redirect's
    Referrer-Policy. This would have potentially resulted in more information than intended by the original
    origin being provided to the destination of the redirect. (CVE-2021-23971)

  - When accepting a malicious intent from other installed apps, Firefox for Android accepted manifests from
    arbitrary file paths and allowed declaring webapp manifests for other origins. This could be used to gain
    fullscreen access for UI spoofing and could also lead to cross-origin attacks on targeted
    websites.Note: This issue is a different issue from CVE-2020-26954 and only affected Firefox for
    Android. Other operating systems are unaffected. (CVE-2021-23976)

  - Firefox for Android suffered from a time-of-check-time-of-use vulnerability that allowed a malicious
    application to read sensitive data from application directories.Note: This issue is only affected
    Firefox for Android. Other operating systems are unaffected. (CVE-2021-23977)

  - One phishing tactic on the web is to provide a link with HTTP Auth. For example
    https://www.phishingtarget.com@evil.com. To mitigate this type of attack, Firefox will
    display a warning dialog; however, this warning dialog would not have been displayed if evil.com used a
    redirect that was cached by the browser. (CVE-2021-23972)

  - The developer page about:memory has a Measure function for exploring what object types the browser has
    allocated and their sizes. When this function was invoked; we incorrectly called the sizeof function,
    instead of using the API method that checks for invalid pointers. (CVE-2021-23975)

  - When trying to load a cross-origin resource in an audio/video context a decoding error may have resulted,
    and the content of that error may have revealed information about the resource. (CVE-2021-23973)

  - Mozilla developers Alexis Beingessner, Tyson Smith, Nika Layzell, and Mats Palmgren reported memory safety
    bugs present in Firefox 85 and Firefox ESR 78.7. Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2021-23978)

  - Mozilla developers Tyson Smith, Lars T Hansen, Valentin Gosu, and Sebastian Hengst reported memory safety
    bugs present in Firefox 85. Some of these bugs showed evidence of memory corruption and we presume that
    with enough effort some of these could have been exploited to run arbitrary code. (CVE-2021-23979)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-07/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 86.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23979");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include('mozilla_version.inc');

kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'86.0', xss:TRUE, severity:SECURITY_WARNING);
