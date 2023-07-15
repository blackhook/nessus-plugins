#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160239);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/29");

  script_cve_id("CVE-2022-20788");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86661");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86671");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz16262");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa91925");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-xss-6MCe4kPF");
  script_xref(name:"IAVA", value:"2022-A-0178");

  script_name(english:"Cisco Unified Communications Products XSS (cisco-sa-cucm-xss-6MCe4kPF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco Unified Communications Manager (Unified CM), Cisco 
Unified CM Session Management Edition (Unified CM SME), and Cisco Unity Connection could allow an unauthenticated, 
remote attacker to conduct a cross-site scripting (XSS) attack against a user of the interface. This vulnerability 
exists because the web-based management interface does not properly validate user-supplied input. An attacker could 
exploit this vulnerability by persuading a user of the interface to click a crafted link. A successful exploit could 
allow the attacker to execute arbitrary script code in the context of the affected interface or access sensitive 
browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-xss-6MCe4kPF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc852d9f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86661");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86671");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz16262");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa91925");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvy86661, CSCvy86671, CSCvz16262, CSCwa91925");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20788");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/27");

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

# 11.5(1)SU11 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-1151su11.html
# 12.5(1)SU6 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-1251su6.html
# 14SU1 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-14su1.html
var vuln_ranges = [
  {'min_ver' : '11.5.1', 'fix_ver' : '11.5.1.23900.30'},
  {'min_ver' : '12.5.1', 'fix_ver' : '12.5.1.16900.48'},
  {'min_ver' : '14.0.1', 'fix_ver' : '14.0.1.11900.132'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvy86661, CSCvy86671, CSCvz16262, CSCwa91925',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);