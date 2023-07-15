##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160404);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3578");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu75615");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-rule-bypass-P73ABNWQ");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software WebVPN Portal Access Rule Bypass Vulnerability Vulnerability (cisco-sa-asaftd-rule-bypass-P73ABNWQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-asaftd-rule-bypass-P73ABNWQ)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability. 
This vulnerability could allow an unauthenticated, remote attacker to bypass a configured access rule and access parts 
of the WebVPN portal that are supposed to be blocked. The vulnerability is due to insufficient validation of URLs when
portal access rules are configured. An attacker could exploit this vulnerability by accessing certain URLs on the 
affected device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-rule-bypass-P73ABNWQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b29a97cf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu75615");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu75615");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3578");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.2.2', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.2.3', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.3.0', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.4.0', 'fix_ver': '6.4.0.10'},
  {'min_ver': '6.5.0', 'fix_ver': '6.5.0.5'},
  {'min_ver': '6.6.0', 'fix_ver': '6.6.1'}
];  

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['portal_access_rule'],
  WORKAROUND_CONFIG['anyconnect_or_ssl'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu75615',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
