#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150279);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2021-1502");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx30404");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-player-dOJ2jOJ");
  script_xref(name:"IAVA", value:"2021-A-0260");

  script_name(english:"Cisco Webex Network Recording Player and Webex Player Memory Corruption (cisco-sa-webex-player-dOJ2jOJ)");

  script_set_attribute(attribute:"synopsis", value:
"The video player installed on the remote host is affected by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Webex Network Recording Player and Cisco Webex Player installed on the remote host is affected by 
a memory corruption vulnerability due to insufficient validation of Webex recording files formatted as either Advanced 
Recording Format (ARF) or Webex Recording Format (WRF). allow an attacker to execute arbitrary code

An unauthenticated remote attacker could exploit this to execute arbitrary code, by sending a malicious ARF or WRF file 
to a user through a link or email attachment and persuading the user to open the file on the local system to execute 
arbitrary code with the same privileges of the targeted user. Please see the included Cisco BIDs and Cisco Security 
Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-player-dOJ2jOJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb85ad4c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx30404");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx30404");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1502");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_advanced_recording_format_player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webex_player_installed.nasl");
  script_require_keys("installed_sw/WebEx ARF/WRF Player");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'WebEx ARF/WRF Player';
var app_info = vcf::get_app_info(app:app);

var constraints = [
     {'min_version': '1',  'fixed_version' : '41.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);