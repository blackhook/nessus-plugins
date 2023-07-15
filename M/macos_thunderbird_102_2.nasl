#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-36.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(164352);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/02");

  script_cve_id(
    "CVE-2022-38472",
    "CVE-2022-38473",
    "CVE-2022-38476",
    "CVE-2022-38477",
    "CVE-2022-38478"
  );
  script_xref(name:"IAVA", value:"2022-A-0342-S");

  script_name(english:"Mozilla Thunderbird < 102.2");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 102.2. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2022-36 advisory.

  - An attacker could have abused XSLT error handling to associate attacker-controlled content with another
    origin which was displayed in the address bar. This could have been used to fool the user into submitting
    data intended for the spoofed origin. (CVE-2022-38472)

  - A cross-origin iframe referencing an XSLT document would inherit the parent domain's permissions (such as
    microphone or camera access). (CVE-2022-38473)

  - A data race could occur in the <code>PK11ChangePW</code> function, potentially leading to a use-after-free
    vulnerability.  In Thunderbird, this lock protected the data when a user changed their master password.
    (CVE-2022-38476)

  - Mozilla developer Nika Layzell and the Mozilla Fuzzing Team reported memory safety bugs present in
    Thunderbird 102.1. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. (CVE-2022-38477)

  - Members the Mozilla Fuzzing Team reported memory safety bugs present in Thunderbird 102.1 and Thunderbird
    91.12. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. (CVE-2022-38478)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-36/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 102.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38478");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Thunderbird';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Thunderbird installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'102.2', severity:SECURITY_HOLE);
