##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163056);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/13");

  script_cve_id("CVE-2022-20752");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz16266");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucm-timing-JVbHECOK");
  script_xref(name:"IAVA", value:"2022-A-0266");

  script_name(english:"Cisco Unified Communications Manager Timing Attack (cisco-sa-ucm-timing-JVbHECOK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications Manager installed on the remote device is version 12.5(1) prior to
12.5(1)SU6 or 14 prior to 14SU1. It is, therefore, affected by a timing attack due to insufficient protection of a
system password. An unauthenticated remote attacker can exploit this vulnerability to determine a sensitive system
password.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucm-timing-JVbHECOK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95893106");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz16266");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz16266");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(208);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# http://www.nessus.org/u?dd376e97
var vuln_ranges = [
  # https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/12_5_1/SU6/cucm_b_release-notes-for-cucm-imp-1251su6.html
  { 'min_ver' : '12.5.1', 'fix_ver': '12.5.1.16900.48'},
  # https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/14_0_1/SU1/cucm_b_release-notes-for-cucm-imp-14su1.html
  { 'min_ver' : '14.0',  'fix_ver' : '14.0.1.11900.132'}
];

var reporting = make_array(
  'port', 0,
  'severity', SECURITY_WARNING,
  'version', product_info['display_version'],
  'bug_id', 'CSCvz16266',
  'fix', 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
