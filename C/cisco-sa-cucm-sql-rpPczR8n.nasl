#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170514);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/01");

  script_cve_id("CVE-2023-20010");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb37205");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb37563");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-sql-rpPczR8n");
  script_xref(name:"IAVA", value:"2023-A-0055");

  script_name(english:"Cisco Unified Communications Manager SQLi (cisco-sa-cucm-sql-rpPczR8n)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications installed on the remote host is prior to tested version. It is, therefore,
affected by an SQL injection vulnerability in the web-based management interface as referenced in the
cisco-sa-cucm-sql-rpPczR8n advisory. An attacker authenticated as a low-privileged user can exploit exploit this
vulnerability by sending crafted SQL queries to an affected system, allowing them to read or modify any data on
the underlying database or elevate their privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-sql-rpPczR8n
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fefa025e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb37205");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb37563");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwb37205, CSCwb37563");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20010");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

var vuln_ranges = [
    # 12.5(1)SU7 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-1251su7.html
    {'min_ver': '11.5.1', 'fix_ver': '12.5.1.17900.64'},
    # 14SU2 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-14su2.html
    # with an additional bump due to 14SU3 not being available yet
    {'min_ver': '14.0', 'fix_ver': '14.0.1.12900.162'}
];

var fix;
if (product_info.version =~ "^14\.")
  fix = 'See vendor advisory';
else
  fix = '12.5(1)SU7';

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'fix'      , fix,
  'bug_id'   , 'CSCwb37205 and CSCwb37563',
  'sqli'     , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);

