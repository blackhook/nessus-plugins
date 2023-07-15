#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169426);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2022-20964",
    "CVE-2022-20965",
    "CVE-2022-20966",
    "CVE-2022-20967"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc98823");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc98828");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc98831");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc98833");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-7Q4TNYUx");
  script_xref(name:"IAVA", value:"2022-A-0462");

  script_name(english:"Cisco Identity Services Engine Vulnerabilities (cisco-sa-ise-7Q4TNYUx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by multiple
vulnerabilities.

  - A vulnerability in the web-based management interface of Cisco ISE could allow an authenticated, remote 
  attacker to inject arbitrary commands on the underlying operating system. (CVE-2022-20964)

  - A vulnerability in the web-based management interface of Cisco ISE could allow an authenticated, remote 
  attacker to conduct cross-site scripting attacks against other users of the application web-based management
  interface. (CVE-2022-20966)

  - A vulnerability in the web-based management interface External RADIUS Server feature of Cisco ISE could 
  allow an authenticated, remote attacker to conduct cross-site scripting attacks against other users of the
  application web-based management interface. (CVE-2022-20967)

  - A vulnerability in the web-based management interface of Cisco ISE could allow an authenticated, remote 
  attacker to bypass security restrictions within the web-based management interface. (CVE-2022-20965)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-7Q4TNYUx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab0b1912");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc98823");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc98828");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc98831");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc98833");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwc98823, CSCwc98828, CSCwc98831, CSCwc98833");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20964");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78, 79, 648);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

# Paranoid due to the existance of hotfixes
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [ 
  {'min_ver':'0.0', 'fix_ver':'2.7.0.356', required_patch:'9'},
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356', required_patch:'9'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458', required_patch:'7'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'6'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'1'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'xss':TRUE},
  'bug_id'        , 'CSCwc98823, CSCwc98828, CSCwc98831, CSCwc98833',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
