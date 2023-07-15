#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-48.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154820);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/17");

  script_cve_id(
    "CVE-2021-38503",
    "CVE-2021-38504",
    "CVE-2021-38505",
    "CVE-2021-38506",
    "CVE-2021-38507",
    "CVE-2021-38508",
    "CVE-2021-38509",
    "CVE-2021-38510"
  );
  script_xref(name:"IAVA", value:"2021-A-0527-S");

  script_name(english:"Mozilla Firefox < 94.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 94.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2021-48 advisory.

  - The iframe sandbox rules were not correctly applied to XSLT stylesheets, allowing an iframe to bypass
    restrictions such as executing scripts or navigating the top-level frame. (CVE-2021-38503)

  - When interacting with an HTML input element's file picker dialog with <code>webkitdirectory</code> set, a
    use-after-free could have resulted, leading to memory corruption and a potentially exploitable crash.
    (CVE-2021-38504)

  - Microsoft introduced a new feature in Windows 10 known as Cloud Clipboard which, if enabled, will record
    data copied to the clipboard to the cloud, and make it available on other computers in certain scenarios.
    Applications that wish to prevent copied data from being recorded in Cloud History must use specific
    clipboard formats; and Firefox before versions 94 and ESR 91.3 did not implement them. This could have
    caused sensitive data to be recorded to a user's Microsoft account. This bug only affects Firefox for
    Windows 10+ with Cloud Clipboard enabled. Other operating systems are unaffected. (CVE-2021-38505)

  - Through a series of navigations, Firefox could have entered fullscreen mode without notification or
    warning to the user. This could lead to spoofing attacks on the browser UI including phishing.
    (CVE-2021-38506)

  - The Opportunistic Encryption feature of HTTP2 (RFC 8164) allows a connection to be transparently upgraded
    to TLS while retaining the visual properties of an HTTP connection, including being same-origin with
    unencrypted connections on port 80.  However, if a second encrypted port on the same IP address (e.g. port
    8443) did not opt-in to opportunistic encryption; a network attacker could forward a connection from the
    browser to port 443 to port 8443, causing the browser to treat the content of port 8443 as same-origin
    with HTTP.  This was resolved by disabling the Opportunistic Encryption feature, which had low usage.
    (CVE-2021-38507)

  - By displaying a form validity message in the correct location at the same time as a permission prompt
    (such as for geolocation), the validity message could have obscured the prompt, resulting in the user
    potentially being tricked into granting the permission. (CVE-2021-38508)

  - Due to an unusual sequence of attacker-controlled events, a Javascript <code>alert()</code> dialog with
    arbitrary (although unstyled) contents could be displayed over top an uncontrolled webpage of the
    attacker's choosing. (CVE-2021-38509)

  - The executable file warning was not presented when downloading .inetloc files, which can run commands on a
    user's computer. Note: This issue only affected Mac OS operating systems. Other operating systems are
    unaffected. (CVE-2021-38510)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-48/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 94.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'94.0', severity:SECURITY_HOLE);
