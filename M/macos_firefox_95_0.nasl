#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-52.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155918);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/10");

  script_cve_id(
    "CVE-2021-4128",
    "CVE-2021-4129",
    "CVE-2021-43536",
    "CVE-2021-43537",
    "CVE-2021-43538",
    "CVE-2021-43539",
    "CVE-2021-43540",
    "CVE-2021-43541",
    "CVE-2021-43542",
    "CVE-2021-43543",
    "CVE-2021-43544",
    "CVE-2021-43545",
    "CVE-2021-43546"
  );
  script_xref(name:"IAVA", value:"2021-A-0569-S");

  script_name(english:"Mozilla Firefox < 95.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 95.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2021-52 advisory.

  - Under certain circumstances, asynchronous functions could have caused a navigation to fail but expose the
    target URL. (CVE-2021-43536)

  - An incorrect type conversion of sizes from 64bit to 32bit integers allowed an attacker to corrupt memory
    leading to a potentially exploitable crash. (CVE-2021-43537)

  - By misusing a race in our notification code, an attacker could have forcefully hidden the notification for
    pages that had received full screen and pointer lock access, which could have been used for spoofing
    attacks. (CVE-2021-43538)

  - Failure to correctly record the location of live pointers across wasm instance calls resulted in a GC
    occurring within the call not tracing those live pointers. This could have led to a use-after-free causing
    a potentially exploitable crash. (CVE-2021-43539)

  - WebExtensions with the correct permissions were able to create and install ServiceWorkers for third-party
    websites that would not have been uninstalled with the extension. (CVE-2021-43540)

  - When invoking protocol handlers for external protocols, a supplied parameter URL containing spaces was not
    properly escaped. (CVE-2021-43541)

  - Using XMLHttpRequest, an attacker could have identified installed applications by probing error messages
    for loading external protocols. (CVE-2021-43542)

  - Documents loaded with the CSP sandbox directive could have escaped the sandbox's script restriction by
    embedding additional content. (CVE-2021-43543)

  - When receiving a URL through a SEND intent, Firefox would have searched for the text, but subsequent
    usages of the address bar might have caused the URL to load unintentionally, which could lead to XSS and
    spoofing attacks. This bug only affects Firefox for Android. Other operating systems are unaffected.
    (CVE-2021-43544)

  - Using the Location API in a loop could have caused severe application hangs and crashes. (CVE-2021-43545)

  - It was possible to recreate previous cursor spoofing attacks against users with a zoomed native cursor.
    (CVE-2021-43546)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-52/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 95.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43539");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'95.0', xss:TRUE, severity:SECURITY_WARNING);
