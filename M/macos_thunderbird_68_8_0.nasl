#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-18.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(136358);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/14");

  script_cve_id(
    "CVE-2020-6831",
    "CVE-2020-12387",
    "CVE-2020-12392",
    "CVE-2020-12393",
    "CVE-2020-12395",
    "CVE-2020-12397"
  );
  script_xref(name:"MFSA", value:"2020-18");
  script_xref(name:"IAVA", value:"2020-A-0190-S");

  script_name(english:"Mozilla Thunderbird < 68.8.0");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 68.8.0. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2020-18 advisory. Note that Nessus has not tested for this issue
but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-18/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 68.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12395");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'68.8.0', severity:SECURITY_HOLE);

