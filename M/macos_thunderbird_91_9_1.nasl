## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-19.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(161411);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2022-1529", "CVE-2022-1802");
  script_xref(name:"IAVA", value:"2022-A-0217-S");

  script_name(english:"Mozilla Thunderbird < 91.9.1");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 91.9.1. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2022-19 advisory.

  - If an attacker was able to corrupt the methods of an Array object in JavaScript via prototype pollution,
    they could have achieved execution of attacker-controlled JavaScript code in a privileged context.
    (CVE-2022-1802)

  - An attacker could have sent a message to the parent process where the contents were used to double-index
    into a JavaScript object, leading to prototype pollution and ultimately attacker-controlled JavaScript
    executing in the privileged parent process. (CVE-2022-1529)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-19/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 91.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1802");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'91.9.1', severity:SECURITY_HOLE);
