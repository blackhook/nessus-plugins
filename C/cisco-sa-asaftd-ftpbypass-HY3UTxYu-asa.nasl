#TRUSTED 2f009fada9f8af36b69a115c487f9e811b9aeed7380bc48358df87faad64ddb47c2f4612067077c2b3324c4eb9d9d5eea67991ba274f1f3bd6056cc6f47cbe3e134274801266dd6c64201f55206f068df6bdc4e0c45b438084ecad09451ed16c968792e4a032a66e10e11670b24e4c2217c05d0e79ec5f659543ca48ca32aa020cbd1745b24c2f9a13dd0199b8b68bc35e579cdbac2d0157e22b8c6760192980382a0a06a5a40e13c697ede74944ae0c8adef6ac8f862ffb5e96329530d14acff5ff0d7086a47345379f3ed03b263e2d47abf3fb72270813c13f797e7b49365d97b4f09731394cc71ebebbf714570366df2634e410610ac88ad04027291dbd93751129e611c58480fae70132f6761da461282ec5e853c99a530161d2cd724d6bf7e2b36e2a484d63441b952763964c680ad866ff7ceb5a2f4e963874b4dd73ed70743ed0b2c0d11203c8f3469f8affdb65a66466ed270eb2e2474943aed227dc1813359eb6296a0613ef3f7e6930e5458dfb161f438a3688a0901ab0011b26d54ad9d8c8123d9810d4edc25c36b00abeee4a561026670d1ba407e419f9a3d3c5992a672a1dced4ad168a43ec51278fb3ba509ddb2eea741e4b9da04efd524e1062965a3556ccb1e958e861bfca2a7eb008b9e75285bb319c5aa91a422a4bd3641c96e5fd87486ce99eeee7e7ba9a432e318b34c01f41f0858b246fe71f338358
#TRUST-RSA-SHA256 a0c3a8cda0a7e89dfe03cff74face33a44b3d038226b25fb2678f9b2b631452c82b9eaf06004a82b62c0f9a603c33ce8057117778be76bd9c03ca9fc795a6f51f50d57b84c18ecc34f3e9c52761c7adf407fda696c9f31088c4c9ce8d1316d52302b68ee66d9803f235265d1d8d5e5ef6a5ff67b597509d801a78ecdefcbbde94697931ab7b3f8e720c95fff12827ad00eb6cc9fb74eef52deb993196a863f6b7a25e92797674f17d678c714153d8157707320a9f7f64b8055b2332bdf3c4b1357afcdbd7ab8e0df07a4aad5fe1d6efdc4bc3b2b1a1bd56b879dba5197d35cd3451c2c03c9771a98c9512140cae3095ac82a2db2dce286bc4770e203ca55b8827a528ad547e42e12bee0b44f9eda68d2d45cfd580235aff87e6c8ec146ef5516a3958a7c90c7f37dfa4a5c431de58e27fffdfc416ee4539f58fee90f0e976ac9480b5937ff9f41ebfab5ba02499001c745c53d94cf16cdf3b8a676b41caee69eda6c245573b9dbe2cb2f215fdb8182db5ab0c9e339212d05a17fc4c474ba977196a968a5a6d6c5d63ae58c4870cd6d8516c727271dad2e97a5186b0fa957320503150cc9b7f813f6ee37e328c4bc4cf1aae73123eb99ee4586ccaaeb692d268ec61a1e0a9b9b152f80bc88b78c048f6db434446bbaf08661fe275ffc77c5ff28c7919cc9ddc709796c4dea00e1be6bb90e0692c3e79ef2a17c3ecba2180f83a9
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164350);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3564");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt13445");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ftpbypass-HY3UTxYu");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Adaptive Security Appliance (ASA) Software FTP Inspection Bypass Vulnerability (cisco-sa-asaftd-ftpbypass-HY3UTxYu)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-asaftd-ftpbypass-HY3UTxYu)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, there is a vulnerability in the FTP inspection engine of Cisco Adaptive
Security Appliance (ASA) Software that could allow an unauthenticated, remote attacker to bypass FTP inspection. The 
vulnerability is due to ineffective flow tracking of FTP traffic. An attacker could exploit this vulnerability by 
sending crafted FTP traffic through an affected device. A successful exploit could allow the attacker to bypass FTP 
inspection and successfully complete FTP connections.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ftpbypass-HY3UTxYu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf58e222");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt13445");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt13445");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3564");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");


  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.26'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.80'},
  {'min_ver': '9.10', 'fix_ver': '9.10.1.44'},
  {'min_ver': '9.12', 'fix_ver': '9.12.4.2'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.13'},
  {'min_ver': '9.14', 'fix_ver': '9.14.1.19'}
];  

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['inspect_ftp_strict'],
  {'require_all_generic_workarounds': TRUE}
];  

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt13445',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);