#TRUSTED aabe3f8c8ca7b5bd0412ad9a0982bb021b75b89dfeb49b6d4848f44bee1ec4154dae0126152ddd8a0251163de02522d457277818e712af14eeacff08da65e44eb533eef298b57102310c8415fc283ea0b023288d599743dc53aff8dd888d9d42ee29cec00015f7a7891871a101e7514462102f79177800e8883c0b97e8648560724c0a343c27a2343d98222f9d8f6dcc03a760643ea03a666f489861ac4c80292cedcc6e4ff14d37f6ccbf19eaf02f4ebb2af5266bd585cb12684b2b348fdfa119fe26ef8aa968c623a0a202ab016987926784337b13947abac87bf2c6e08f930d418ad51d03ebb88e0262338521fb57a877ea64a84fe8e74d26029d2c81443d7d4d3d838abeb94e18f5bcdbc4d19510cb2abf3c89a7082eb669bb77d12b0d176fa06bb414e60bdea31cdd80d8e7b14c8bd1e481ad4ffc12c0b811a00574d2d17c105bb15b735d28464073246fecfde8f9658de4504c77f1030779078ca9e6a71a3f87d4e733b3cfa377f8216f49e3fe7f6e47f29c77c8677599ddb79a4ae78ddce31fb6ef5461f678d1cd1548ae9ba0b6cc08ff32d6eff6b518d7155c4cb2108d82dd100bb2743eaaf9d7106073201e9989dee0ef4f50ab6d3c501abfc836204fd6c0531b206175f14b9fa999ce20d4d5f3c0405f713e6fc98ce7c8d5e9dbac8b2be20c97f4c7a4146784480967d20c9ab97823b493c6457ee654b1899197c3
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146202);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/23");

  script_cve_id("CVE-2021-1223");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu18635");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-filepolbypass-67DEwMe2");
  script_xref(name:"IAVA", value:"2021-A-0027-S");

  script_name(english:"Cisco Integrated Services Routers 1000/4000 Series HTTP Detection Engine File Policy Bypass (cisco-sa-snort-filepolbypass-67DEwMe2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Software
running on the remote Integrated Services Router device is affected by affected by a file policy bypass vulnerability 
due to the incorrect handling of a HTTP range header. An unauthenticated, remote attacker could send a carefully 
crafted malicious payload to the device bypass file policy configurations");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-filepolbypass-67DEwMe2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac01012e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu18635");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu18635");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1223");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

if (product_info['model'] !~ "^ISR[14]\d{3}([^0-9]|$)")
  audit(AUDIT_HOST_NOT, 'an affected model');

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var vuln_ranges = [{'min_ver' : '0.0.0', 'fix_ver' : '17.4.1'}];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu18635',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,  
  router_only:TRUE
);