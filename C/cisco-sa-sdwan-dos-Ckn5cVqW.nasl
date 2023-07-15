#TRUSTED a18be0382ed4c7bafea709eadfe4343e7c3150831cf1f0ef879c88b0638388cc79c1bb499ab7a7e75c0bfddfb3d7f84c9fbcc673c703f4882ea55f05d7669cf8e10838c091e290ee6f255408a2f9bc0da1e1dddf318d7e8d428167686b9001f8e2b3b37f366a129ca9fa4894d44ff2ada670bf8119fd30b5e30637469769e47bfe49780d9dfd3b33e4e2a07ded872d71c1f404224c6b0070cc06143f3c421cfc58b125d790fe9e1f81691d33202225e80a631d64aa883b474cb6d640fb196905caa6551856789cac56413eba0dda1a985297901473e21c8583e273b06eec312754c482086e114442964f0a6651f95e196f8813747d1315675441f15ff2fed795dd76f8fba81662ea0d15398b2c55f86f3bf65907c011cc271462eb6cfa90353c269afb00446920cfaf5e82c8e057a03039030ef898664d1b6acb0d70f11f9a5c42a0eb462d4ff172ad882a1d4607702c9fa81071f7a2dc19e7517557d708ff9b2269187e5d9678d8b9c46da6f5f7b7ba39bbbdbd08d34824639e4268e26b136c8ac4434cfc1e3461291653f17c062b5c2ed6f2d8234d89b5e845f0eb4e5dd45d525f235e8efb81cab31ac21e51de39a6a452f688e9669f9a006f0ec566ed7de30ca0928e3112809d112b6c38d274d0a14807847ca157afba68aed19a9f1098ade361dbfb51e1deba6350559d7e970d41eac3cf5b03803c0b05fc81703a613f9b
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150990);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/24");

  script_cve_id("CVE-2021-1513");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28378");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-dos-Ckn5cVqW");

  script_name(english:"Cisco SD-WAN Software vDaemon DOS (cisco-sa-sdwan-dos-Ckn5cVqW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-dos-Ckn5cVqW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14ae40a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28378");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu28378");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
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
  { 'min_ver' : '0.0', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu28378',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
