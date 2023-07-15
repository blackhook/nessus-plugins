#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-51.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(168652);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2022-46871",
    "CVE-2022-46872",
    "CVE-2022-46873",
    "CVE-2022-46874",
    "CVE-2022-46875",
    "CVE-2022-46877",
    "CVE-2022-46878",
    "CVE-2022-46879"
  );
  script_xref(name:"IAVA", value:"2022-A-0517-S");
  script_xref(name:"IAVA", value:"2023-A-0009-S");
  script_xref(name:"IAVA", value:"2023-A-0056-S");

  script_name(english:"Mozilla Firefox < 108.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 108.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2022-51 advisory.

  - An out of date library (libusrsctp) contained vulnerabilities that could potentially be exploited.
    (CVE-2022-46871)

  - An attacker who compromised a content process could have partially escaped the sandbox to read arbitrary
    files via clipboard-related IPC messages. This bug only affects Firefox for Linux. Other operating systems
    are unaffected. (CVE-2022-46872)

  - Because Firefox did not implement the <code>unsafe-hashes</code> CSP directive, an attacker who was able
    to inject markup into a page otherwise protected by a Content Security Policy may have been able to inject
    executable script.  This would be severely constrained by the specified Content Security Policy of the
    document. (CVE-2022-46873)

  - A file with a long filename could have had its filename truncated to remove the valid extension, leaving a
    malicious extension in its place. This could have potentially led to user confusion and the execution of
    malicious code. (CVE-2022-46874)

  - The executable file warning was not presented when downloading .atloc and .ftploc files, which can run
    commands on a user's computer.  Note: This issue only affected Mac OS operating systems. Other operating
    systems are unaffected. (CVE-2022-46875)

  - By confusing the browser, the fullscreen notification could have been delayed or suppressed, resulting in
    potential user confusion or spoofing attacks. (CVE-2022-46877)

  - Mozilla developers Randell Jesup, Valentin Gosu, Olli Pettay, and the Mozilla Fuzzing Team reported memory
    safety bugs present in Firefox 107 and Firefox ESR 102.5. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code. (CVE-2022-46878)

  - Mozilla developers and community members Lukas Bernhard, Gabriele Svelto, Randell Jesup, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Firefox 107. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. (CVE-2022-46879)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-51/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 108.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46879");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'108.0', severity:SECURITY_HOLE);
