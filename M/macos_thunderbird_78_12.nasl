#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-30.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151612);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2021-29969",
    "CVE-2021-29970",
    "CVE-2021-29976",
    "CVE-2021-30547"
  );
  script_xref(name:"IAVA", value:"2021-A-0293-S");

  script_name(english:"Mozilla Thunderbird < 78.12");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 78.12. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2021-30 advisory.

  - If Thunderbird was configured to use STARTTLS for an IMAP connection, and an attacker injected IMAP server
    responses prior to the completion of the STARTTLS handshake, then Thunderbird didn't ignore the injected
    data. This could have resulted in Thunderbird showing incorrect information, for example the attacker
    could have tricked Thunderbird to show folders that didn't exist on the IMAP server. (CVE-2021-29969)

  - A malicious webpage could have triggered a use-after-free, memory corruption, and a potentially
    exploitable crash. This bug only affected Thunderbird when accessibility was enabled. (CVE-2021-29970)

  - An out of bounds write in ANGLE could have allowed an attacker to corrupt memory leading to a potentially
    exploitable crash. (CVE-2021-30547)

  - Mozilla developers Valentin Gosu, Randell Jesup, Emil Ghitta, Tyson Smith, and Olli Pettay reported memory
    safety bugs present in Thunderbird 78.11. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2021-29976)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-30/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 78.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include('mozilla_version.inc');

kb_base = 'MacOSX/Thunderbird';
get_kb_item_or_exit(kb_base+'/Installed');

version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Thunderbird installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'78.12', severity:SECURITY_WARNING);
