#TRUSTED 41c844c5bfea580642d6d6ad87208701579557340182a1a224377a447f912ef364dc4e773f7c5104d566f99e65dcd587c33cdb86c5bf45aa97b9620b05f93ef52abbcf121a9c49350611624b85527f88aac6bb03f83c40d0d2cb3aec54f3efade5c54256c159ecc808d67588b4cc17f39aa89b98d780f663640aaae319ee1225ba8381b80c53d1193bcb25cdc13241102102bce90e38a851779ec88e0e4ca8057e5c07d3d2c9515a0d80f48f595c83f8db56463467064562f865041b0128cf79b2bc13b247497e42fc54dffc0f501d0d2f2041afd9923d5e4e7ed3c415b6736d6833d3f74a00bbcbcdbe2de71dbbcca596116145301c71ad67d13d7bb3f52df00f13a6ed4a2969d351a31fd418512c3b1d9476ef0cec9cbcf51ded982bf727072b6b0496807ff15573636c61811b1ee6891e0d3b6423fd5798ff604d6a908b2890b50ebce9dd2908948fe049df7a2b4ef5c4eab6a4e3c05cb82e40a0abd2a352103905ef232b2166e56bb914567d81aec43ac1313973709cb3d45c5f9d5e3f80fb1728999dec7ae08f42d1fe28013f216c6afc4b53125dd14145ebfd2718d87ca179c6db7e7682cc045ec248e7bb8c196760d7ce9e2c1b5248f03541f53d6ef2623933da828c7481d5307b286e66b7009df735d73b707f9120ec38881aee3eb565fca505a367b50ed6fb32f39f254b2d70a38c160f5e37ff0e46ea282ffbd174
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151483);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/12");

  script_cve_id("CVE-2020-3371");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf61055");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv12621");
  script_xref(name:"CISCO-SA", value:"cisco-sa-CIMC-CIV-pKDBe9x5");
  script_xref(name:"IAVA", value:"2019-A-0312-S");

  script_name(english:"Cisco Integrated Management Controller Command Injection (cisco-sa-CIMC-CIV-pKDBe9x5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Integrated Management Controller (IMC) is affected by a vulnerability in
the web UI that allows an authenticated, remote attacker to inject arbitrary code and execute arbitrary commands at the
underlying operating system level. The vulnerability is due to insufficient input validation. An attacker could exploit
this vulnerability by sending crafted commands to the web-based management interface of the affected software. A
successful exploit could allow the attacker to inject and execute arbitrary commands at the underlying operating system
level.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-CIMC-CIV-pKDBe9x5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0c73290");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf61055");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv12621");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvf61055, CSCvv12621");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3371");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Computing System (Management Software)');

var vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '3.0(3e)' }
];


var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf61055, CSCvv12621'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
