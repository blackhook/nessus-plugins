#TRUSTED 88f2dafe05279e7b088b9701b6e088fa0304348a2ccf40ec2dee46158408100250e4bdef26776ac936cbfb274957989c0fc67d37edfe68bc17136a80a2a17537273293e7c3e4f95489ad760e1c24058c02cb3123633bf87417f8ead0c2290aa1b7b87d08bab71f176024ee29a904f975d008e2e34b6d738fc91b053699c81570e9a919259530a5a0040d72c46975f7a4cc5c933218aad83e9b282ae9202e0f71e456dbe2103ececd49f9a0f0a8252b18dcd57275e3e31d8b331cfbd4c3a698ee795b97f01e05b348a9d135e533a27b14b396aae871aa35e36e12efc60594862a89047f093e675e08a1cedd1fd6f17daccb450060691a809198559fa326ded176a8aa055d5b31231fac9912cb582326fa3fe4f4ffca49ff3c20ad702cf27f5d3578dd7cebe7c9dedaa373ec5eb5dde8bb8a78db52b816cd83f6f36ce6f522917006b2ab89f8efd70709a12ca002f40eaf6b3993b299880210cbdcd7ef27a99031de7ec81080ea1b7bb96f88a2700676041ffd0101861afad70ef2a798d9a67e0f8c3fb2af1f61a37c7dae00fd3c887284d1557cb31fd23dee19cfa118c37a5d415efdf0ab5d6795a005bcb10187cd0955c0891f46c0519448371c82b46a7a496a9cd9d1beb2319cdf2144fbeb3b20efa5f54f5098b69fca2e12e05e90321bd15cf79864f26cfbeeba095f65885dc1dfa7b39c95e89935bd2e1b53fcec1ab3f00e
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149327);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_cve_id("CVE-2021-1515");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28372");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-vmanage-9VZO4gfU");

  script_name(english:"Cisco SD-WAN vManage Information Disclosure (cisco-sa-sd-wan-vmanage-9VZO4gfU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by an information disclosure
vulnerability due to improper access controls on API endpoints when running in multi-tenant mode. An unauthenticated,
adjacent attacker can exploit this, by sending a request to an affected API endpoint on the vManage system, to gain
access to sensitive information that may include hashed credentials.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-vmanage-9VZO4gfU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1daa9a91");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28372");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu28372.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.4.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvu28372',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
