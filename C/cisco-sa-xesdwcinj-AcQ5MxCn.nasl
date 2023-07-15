#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138876);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2019-16011");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs75505");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xesdwcinj-AcQ5MxCn");
  script_xref(name:"IAVA", value:"2020-A-0189");

  script_name(english:"Cisco IOS XE SD-WAN Software Command Injection Vulnerability (cisco-sa-xesdwcinj-AcQ5MxCn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by a command injection vulnerability. An authenticated
attacker could allow to execute arbitrary command with root privileges due to insufficient input validation. 
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xesdwcinj-AcQ5MxCn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5170d3aa");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs75505");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs75505");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16011");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

version_list=make_list(
  '16.9.4',
  '16.9.3',
  '16.9.2',
  '16.9.1',
  '16.9.0', 
  '16.12.2r',
  '16.12.1e',
  '16.12.1d',
  '16.12.1b',
  '16.12.0',
  '16.11.1a',
  '16.11.0',
  '16.10.4',
  '16.10.3b',
  '16.10.3a',
  '16.10.3',
  '16.10.2',
  '16.10.1',
  '16.10.0'
);

var sdwan = get_kb_item('Host/Cisco/SDWAN/Version');
var model_check = product_info['model'];

#Model checking for IOS XE SDWAN model only
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

if(sdwan !~ "([0-9]\.)+")
  audit(AUDIT_HOST_NOT, 'affected');

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs75505',
  'disable_caveat', TRUE
);
cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_versions:version_list
);