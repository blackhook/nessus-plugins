#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151013);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2021-1526");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx58407");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-player-kOf8zVT");
  script_xref(name:"IAVA", value:"2021-A-0282");

  script_name(english:"Cisco Webex Player Memory Corruption (cisco-sa-webex-player-kOf8zVT)");

  script_set_attribute(attribute:"synopsis", value:

"The remote device is missing a vendor-supplied security patch");
script_set_attribute(attribute:"description", value:
"The version of Cisco Webex Player installed on the remote host is affected by a memory corruption vulnerability due
to insufficient validation of values in Webex recording files that are in Webex Recording Format (WRF). An attacker
could exploit this by sending a user a malicious WRF file through a link or email attachment and persuading the user
to open the file with the affected software on the local system. A successful exploit could allow the attacker to
execute arbitrary code on the affected system with the privileges of the targeted user. Please see the included Cisco
BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-player-kOf8zVT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1805e055");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx58407");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx58407");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_advanced_recording_format_player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

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
     {'fixed_version' : '41.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
