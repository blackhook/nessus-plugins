#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167049);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/08");

  script_cve_id("CVE-2022-20942");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc43104");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cnt-sec-infodiscl-BVKKnUG");
  script_xref(name:"IAVA", value:"2022-A-0463");

  script_name(english:"Cisco Secure Web Appliance Information Disclosure (cisco-sa-cnt-sec-infodiscl-BVKKnUG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Web Appliance is affected by an information disclosure  
vulnerability that could allow an authenticated, remote attacker to retrieve sensitive information from an affected 
device, including user credentials.

This vulnerability is due to weak enforcement of back-end authorization checks. An attacker could exploit this 
vulnerability by sending a crafted HTTP request to an affected device. A successful exploit could allow the attacker to
obtain confidential data that is stored on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cnt-sec-infodiscl-BVKKnUG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e6a1b95");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc43104");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc43104");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20942");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '12.0.5.011'},
  {'min_ver' : '12.5', 'fix_ver' : '12.5.4.005'},
  {'min_ver' : '14.0', 'fix_ver' : '14.0.2.012'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc43104',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);