#TRUSTED 14eba3060076fb2e770bcc8fc101018ab9d3b5d6f4432cf3581bdde3bf34ed8a76f14bf95e29606e4a0664a4fa904354e1a0678fbac1d5093105c85b17f920ff2eaa9e3179a8d4aec1f599ca9969263f39b9d8197a08bd0aeb9e110c376883f964d617af692fbde5109e3638bc90a71990d3ac88d2ba3d5dfbcf93b83beeca8ac45a778e2f5a560099d981a0516a91568854d60dffbf8161de49bd858e1709f8c764eca76508b419fe828fee999e74d8dde961a634ce51819e43c5046fa6799529ae91f6b4eab4b3d33703a4e54363d5465ca321f1fba7c508702806f00e784f3b6ccb3e1571a46c569c1ad6375b2e35a0704e5be7bba6a894d1860b898936a60d4f2d5574b7a680304836fbc5b4f253a404c449fe86cb1997b5bf264ecf123872f1311356d45444715961f04e8b77b7bb002668a539ca47470b78f3209e77c99dfb82b710bbe40343424ed2b28e9f410332100379b1cb9a8625eb91db2f371dc12d43da962e99f42b9f17ac5780b6c035ce7cdbfef3f7498c9ab23a3aae214b6da2ab35bd2c40a3dc9cd9efaa97fd9324627a2175506eedeb855a8ee5b160e0ef4792ff0b4d1ed3380b7ed41f5497c82648a032a99c858ebc489b79e5769ee2a48aa0eef04326d34775b027cd245abaaf259b098a2016880ed0dda4fa349be6f551dccc1ebaed2e7b09e162635e0f5af96bb4258b1b9b1aea097c8b4071ca4c
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159720);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2022-20735");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28364");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vmanage-csrf-rxQL4tXR");

  script_name(english:"Cisco SD-WAN vManage Software XSRF (cisco-sa-sdwan-vmanage-csrf-rxQL4tXR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco SD-WAN vManage Software could allow an
    unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack on an affected
    system. This vulnerability is due to insufficient CSRF protections for the web-based management interface
    on an affected system. An attacker could exploit this vulnerability by persuading a user of the interface
    to click a malicious link. A successful exploit could allow the attacker to perform arbitrary actions with
    the privilege level of the affected user. These actions could include modifying the system configuration
    and deleting accounts. (CVE-2022-20735)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vmanage-csrf-rxQL4tXR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbc1a8d7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28364");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu28364");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.1' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu28364',
  'version'  , product_info['version'],
  'flags', {'xsrf':TRUE},
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
