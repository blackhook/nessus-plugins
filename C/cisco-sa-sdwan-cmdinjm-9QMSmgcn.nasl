#TRUSTED a213fad818914d599d7d05b4eb69915e8a3aca06f0cfbf90a79cf1f2dbd207519e9117b82c9f006a54e4516befade3b0aa94c26d3d2addd40b22cf54466e34e5b980b89574d1dd0519bef1f42080793536d55a381284aa4b298c45720b3355a7dc88b2c9f7d87b6350dc2c8fcc54eeaf0ed01c0cbe669c5b3f669bf6d991100245b10ed142f438fcade1fc43edfc5a7b730874c6ee5ba9877c9fd24485a65ea4e057cb17aee05a442988d4fd3f3883a3e3b33acbdc710124ebcac21c2c957adc9a5a08ea40ddb30a33ef4dd88d1b16d10da05365796e071525f559bbc9c8a4a603f19dc1638edd29341c092aab29409bc49903c8aa097d1afbd1c77575cf5eebe4410ca845cd39c57d9f6adaf5a5aba12885c7c6c36343baa76ed7f795878cc81ac28173c10b4908d7d495399e3e9297ef91035adc41c5f7c3b7580c5cad227dce5603063a1bbcdfeb426f58ca14b3408478a91a6931ab47f23e4f3cd2a2400ff6f822ce71270260855054d230a58a2fdda86a6ca55702bc3c41c6e8cdd416b0115f8ab5f86c02fcc5cb4328fb35a1dcf73fbee6e183c11b3bafb3b5790ef9e3fa3c112695efa85932dc50c29c873a9b8e9f6f7a5d978595f9ef8d0b6891ff9b010b342d65c7783bbc63e5f98a7a94c889401b44c1b8bfcf293ddabd7607f9554d53d0a1f959bd68cc2f1992493af2a7fd60430ecff37fb7620663893c2c0b33
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151132);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id(
    "CVE-2021-1260",
    "CVE-2021-1261",
    "CVE-2021-1262",
    "CVE-2021-1263",
    "CVE-2021-1298",
    "CVE-2021-1299"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi59635");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi59639");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69982");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm26011");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28387");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28443");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-cmdinjm-9QMSmgcn");
  script_xref(name:"IAVA", value:"2021-A-0045");

  script_name(english:"Cisco SD-WAN Command Injection Vulnerabilities (cisco-sa-sdwan-cmdinjm-9QMSmgcn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by multiple vulnerabilities that
allow an authenticated attacker to inject commands and take actions with root privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-cmdinjm-9QMSmgcn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e8bc691");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi59635");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi59639");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69982");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm26011");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28387");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28443");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi59635, CSCvi59639, CSCvi69982, CSCvm26011,
CSCvu28387, CSCvu28443");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1299");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '19.2.4' },
  { 'min_ver' : '19.3', 'fix_ver' : '20.1.2' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.2' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' }
];

var version_list = make_list(
  '19.2.097',
  '19.2.099',
  '19.2.31.0',
  '20.1.12.0'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvi59635, CSCvi59639, CSCvi69982, CSCvm26011, CSCvu28387, CSCvu28443',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
