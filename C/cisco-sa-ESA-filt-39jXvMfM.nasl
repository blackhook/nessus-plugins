#TRUSTED 464d5dbae41e906614a5b283e0fa60d00c8a9f41d467ec6b5d9995e5ddb1d03585305f2354fc20763705875f316ce7a8034882c0ba378996a0e05699f62027dcbed8546f1c0542b069da353b0ada000cb0fc790b4c9522ea6ba5d824375a08267abd0ce0e6809143d426c9af38d0af4350bc6f561d6c1a243925cd45a3cf9a09e43aeaa12f492a2b6aa9bb538e2abc73e4a529f87c7dc02400d80e78e2d2c8331f970ff1a42047e442f99cc5213b11bbfaea7446272eb7b6598ee18848c38b58c1f424051fb70df55d6c42402f35e161d047f27b8c44291ad9f7e3299746f0643db0f84d54340fe0c5c6a7961e4d02925be5b2c7596087f5449bb182d9aaa80ebc3137eb5808f9ce5471050ecec8b6a973dec78f41edc69da488543f449a1e67ae74f9d8157f88c31e601a58ef4d7ca1a3a437898790261dd8b815976e0e59e4f4a01f3b4ba7ca5fb65147b0a253e75af6c34207ab6cd45b49a6e86475a36c61ff4fd5c7bbf5bb53ca656a967c6b42a2b6ffc76fb3a8d1a007681320aea9d4eee4ce2a9c0b624c5955c2ff3b391fd512de98c6a897167ecc0ef056e9d0d521697a849c9f122615d38bac70d247aaec55bf3dba69b5db6431cc0f696a6bf1260cef5df0fda87f743afb005f65dbd14f1c9d0e3199fe308810f78ffbab2f3aac91b8c58f6bb2df460e5708e714fdee6a17e65b1db5c315bb2c6e91942f09c4ef6f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(138881);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/19");

  script_cve_id("CVE-2020-3370");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs58807");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ESA-filt-39jXvMfM");
  script_xref(name:"IAVA", value:"2020-A-0336-S");

  script_name(english:"Cisco Email Security Appliance Filter Bypass (cisco-sa-ESA-filt-39jXvMfM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by an input-validation flaw
related to the URL filtering feature. An unauthenticated, remote attacker can exploit this, by sending a crafted,
malicious HTTP request to an affected device, in order to allow the attacker to redirect users to malicious sites.

Please see the included Cisco BID and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ESA-filt-39jXvMfM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1a93067");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs58807");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs58807");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3370");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '13.0.1' },
  { 'min_ver' : '13.5', 'fix_ver' : '13.5.1' },
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvs58807',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
