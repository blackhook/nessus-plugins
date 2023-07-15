#TRUSTED 5d53473fc88177e9e58aeb300a2ed9b0e95f9ab85222b9e315e3326988f36a811dd9cf5f61529ab36d1583ba0161c42ddae18df0ea5afaf78e0df554c22a65d4216baf627793cf87b1bf526302d96fb0fc252ebf76d29841862df505a77adf314c2b9896912f768b0202a7f1fbd4045adab1350a9cee4a91bd681f932c645a0970380050086f8059add8158ffc0163a2ddbfb0b98ffbe9ecbdeabaf6ef1bb6ef1ace8ce9eebaa2f467eb79c2b7f4582ebc174f73caeea26b3b41736c6b51d84c455daadb8226f32cc494b2b17035ea3ae0e50194be49cb0b0184dc8335a6fb589fdb804d60de6f7d39130b3a60811f9613cba9f58690771a8c29bdf6d4f8557d394b02dd41f42be6226d3bb4e51c3ccf744f12f1ca97b88dd57e066fce5dc6af6ceec3e1aa8ae07ecf0b09b36290bb78ffacede77758a94d4f44752ef8bf3d35b018783762614bd94a0ade88d3e58700d5a42becd637fdf915c0ef851f7b7ab4a80b7ff7ec3b83a914ee8378e784b6e0732b3c01f7b77ef6f4c3dc8699db6be3474a8e58d6a4fce06bf0df080deddebd469fbf512007c739e404e8cf0d6c3740c78ae99a345279dee5dd3cd8399586fed58e35150e4a01f008f09b7b89351d73969d9c9faa6f636ebcf9f4c2db8cbb71c798d52b7d7625d3dbc2f8491a9df77fb7ebe5f9fac50e8020ef8739bc15aff8b4e05e8f5375c374ddea06d71805c1f7
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151661);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/19");

  script_cve_id("CVE-2021-1359");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv81569");
  script_xref(name:"CISCO-SA", value:"cisco-sa-scr-web-priv-esc-k3HCGJZ");
  script_xref(name:"IAVA", value:"2021-A-0305");

  script_name(english:"Cisco Web Security Appliance Privilege Escalation (cisco-sa-scr-web-priv-esc-k3HCGJZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance is affected by a privilege escalation
vulnerability. A vulnerability in the configuration management of Cisco AsyncOS for Cisco Web Security Appliance (WSA)
could allow an authenticated, remote attacker to perform command injection and elevate privileges to root. This
vulnerability is due to insufficient validation of user-supplied XML input for the web interface. An attacker could
exploit this vulnerability by uploading crafted XML configuration files that contain scripting code to a vulnerable
device. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system
and elevate privileges to root. An attacker would need a valid user account with the rights to upload configuration
files to exploit this vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-scr-web-priv-esc-k3HCGJZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4eb0fcf3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv81569");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv81569");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1359");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(112);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');


var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '11.9'},
  { 'min_ver' : '12.0', 'fix_ver' : '12.0.3.005'},
  { 'min_ver' : '12.5', 'fix_ver' : '12.5.2'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv81569',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
); 
