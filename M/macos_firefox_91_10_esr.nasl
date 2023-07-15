## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-21.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(161711);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/09");

  script_cve_id(
    "CVE-2022-31736",
    "CVE-2022-31737",
    "CVE-2022-31738",
    "CVE-2022-31739",
    "CVE-2022-31740",
    "CVE-2022-31741",
    "CVE-2022-31742",
    "CVE-2022-31747"
  );
  script_xref(name:"IAVA", value:"2022-A-0226-S");

  script_name(english:"Mozilla Firefox ESR < 91.10");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 91.10. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2022-21 advisory.

  - A malicious website could have learned the size of a cross-origin resource that supported Range requests.
    (CVE-2022-31736)

  - A malicious webpage could have caused an out-of-bounds write in WebGL, leading to memory corruption and a
    potentially exploitable crash. (CVE-2022-31737)

  - When exiting fullscreen mode, an iframe could have confused the browser about the current state of
    fullscreen, resulting in potential user confusion or spoofing attacks. (CVE-2022-31738)

  - When downloading files on Windows, the % character was not escaped, which could have lead to a download
    incorrectly being saved to attacker-influenced paths that used variables such as %HOMEPATH% or %APPDATA%.
    This bug only affects Firefox for Windows. Other operating systems are unaffected. (CVE-2022-31739)

  - On arm64, WASM code could have resulted in incorrect assembly generation leading to a register allocation
    problem, and a potentially exploitable crash. (CVE-2022-31740)

  - A crafted CMS message could have been processed incorrectly, leading to an invalid memory read, and
    potentially further memory corruption. (CVE-2022-31741)

  - An attacker could have exploited a timing attack by sending a large number of allowCredential entries and
    detecting the difference between invalid key handles and cross-origin key handles.  This could have led to
    cross-origin account linking in violation of WebAuthn goals. (CVE-2022-31742)

  - Mozilla developers Andrew McCreight, Nicolas B. Pierron, and the Mozilla Fuzzing Team reported memory
    safety bugs present in Firefox 100 and Firefox ESR 91.9. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code. (CVE-2022-31747)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-21/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 91.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (isnull(is_esr)) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'91.10', min:'91.0.0', severity:SECURITY_HOLE);
