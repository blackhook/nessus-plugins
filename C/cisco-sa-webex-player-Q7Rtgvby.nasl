#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136120);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/01");

  script_cve_id("CVE-2020-3194");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs56936");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs56937");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs56938");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-player-Q7Rtgvby");
  script_xref(name:"IAVA", value:"2020-A-0182");

  script_name(english:"Cisco Webex Network Recording Player and Cisco Webex Player Arbitrary Code Execution Vulnerability (cisco-sa-webex-player-Q7Rtgvby)");

  script_set_attribute(attribute:"synopsis", value:
"The video player installed on the remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Webex Network Recording Player and Cisco Webex Player installed on the remote host is affected by 
a remote code execution vulnerability due to insufficient validation of certain elements within a Webex recording that 
is stored in either the Advanced Recording Format (ARF) or the Webex Recording Format (WRF). An unauthenticated remote 
attacker could exploit this, by sending a malicious ARF or WRF file to a user through a link or email attachment and 
persuading the user to open the file on the local system to execute arbitrary code with the same privileges of the 
targeted user. Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-player-Q7Rtgvby
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffb021db");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs56936");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs56937");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs56938");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs56936, CSCvs56937, CSCvs56938");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3194");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_advanced_recording_format_player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webex_player_installed.nasl");
  script_require_keys("installed_sw/WebEx ARF/WRF Player");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'WebEx ARF/WRF Player';
app_info = vcf::get_app_info(app:app);

constraints = [
     {'min_version': '39.5',  'fixed_version' : '39.5.18' },
     {'min_version': '40',  'fixed_version' : '40.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
