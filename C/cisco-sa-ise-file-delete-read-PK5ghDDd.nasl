#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176871);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/08");

  script_cve_id("CVE-2023-20106", "CVE-2023-20171", "CVE-2023-20172");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc86067");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd38138");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd63674");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd93718");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-file-delete-read-PK5ghDDd");
  script_xref(name:"IAVA", value:"2023-A-0261");

  script_name(english:"Cisco Identity Services Engine 3.1.x < 3.1P6, 3.2.x < 3.2P2 Arbitrary File Delete and File Read (cisco-sa-ise-file-delete-read-PK5ghDDd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services is affected by a vulnerability in the web-based
management interface. These allow an authenticated, remote attacker to delete or read arbitrary files on the underlying 
operating system. To exploit these vulnerabilities, an attacker must have valid credentials on an affected device. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-file-delete-read-PK5ghDDd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d63e4953");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd79921");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20171");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [ 
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'6'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'2'} 
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc86067, CSCwd38138, CSCwd63674, CSCwd93718',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
