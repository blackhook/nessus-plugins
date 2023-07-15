#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-18.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(175372);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2023-32205",
    "CVE-2023-32206",
    "CVE-2023-32207",
    "CVE-2023-32211",
    "CVE-2023-32212",
    "CVE-2023-32213",
    "CVE-2023-32214",
    "CVE-2023-32215"
  );
  script_xref(name:"IAVA", value:"2023-A-0255-S");

  script_name(english:"Mozilla Thunderbird < 102.11");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 102.11. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2023-18 advisory.

  - In multiple cases browser prompts could have been obscured by popups controlled by content. These could
    have led to potential user confusion and spoofing attacks. (CVE-2023-32205)

  - An out-of-bound read could have led to a crash in the RLBox Expat driver. (CVE-2023-32206)

  - A missing delay in popup notifications could have made it possible for an attacker to trick a user into
    granting permissions. (CVE-2023-32207)

  - A type checking bug would have led to invalid code being compiled. (CVE-2023-32211)

  - An attacker could have positioned a <code>datalist</code> element to obscure the address bar.
    (CVE-2023-32212)

  - When reading a file, an uninitialized value could have been used as read limit. (CVE-2023-32213)

  - Protocol handlers <code>ms-cxh</code> and <code>ms-cxh-full</code> could have been leveraged to trigger a
    denial of service. Note: This attack only affects Windows. Other operating systems are not affected.
    (CVE-2023-32214)

  - Mozilla developers and community members Gabriele Svelto, Andrew Osmond, Emily McDonough, Sebastian
    Hengst, Andrew McCreight and the Mozilla Fuzzing Team reported memory safety bugs present in Thunderbird
    102.10. Some of these bugs showed evidence of memory corruption and we presume that with enough effort
    some of these could have been exploited to run arbitrary code. (CVE-2023-32215)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-18/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 102.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'102.11', severity:SECURITY_HOLE);
