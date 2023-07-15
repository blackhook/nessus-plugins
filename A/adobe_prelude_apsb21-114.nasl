#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156220);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-43754", "CVE-2021-44696");
  script_xref(name:"IAVA", value:"2021-A-0592");

  script_name(english:"Adobe Prelude < 22.1.1 Multiple Vulnerabilities (APSB21-114)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Prelude CC installed on the remote Windows host is prior to 22.1.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB21-114 advisory, including the following:

  - An arbitrary code execution vulnerability exists in Adobe Prelude due to an attempt to access a memory location 
    after the end of buffer. An unauthenticated, local attacker can exploit this to bypass authentication and execute
    arbitrary commands on an affected host (CVE-2021-43754). 
    
  - A privilege escalation vulnerability exists in Adobe Prelude due to an out of bounds read. An unauthenticated, 
    local attacker can exploit this, to escalate their priviliges on an affected hosts (CVE-2021-44696).

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's 
self-reported version number.");
  # https://helpx.adobe.com/security/products/prelude/apsb21-114.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d06449ab");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Prelude version 22.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43754");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:prelude");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_prelude_installed.nasl");
  script_require_keys("installed_sw/Adobe Prelude", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Prelude', win_local:TRUE);
var constraints = [{'fixed_version': '22.1', 'fixed_display': '22.1.1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
