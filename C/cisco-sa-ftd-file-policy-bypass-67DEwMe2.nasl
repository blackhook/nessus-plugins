#TRUSTED b100090d78db8e8e7c58fbbeb84e642e7165a92a31d72871758d58698ea69d376834042a2e2a34617fe0faf2dcdcb6299d109600e48159793b21582bafe5914d7b48ef1d9cba94fcd04c2959f452f6e9da65ef1efbd1377ecf3f6a4db5afff5df084eaed78891ef7358ab8f318a5300121759493778f1145e28955c854a540caae3ae3f3882c7c6aeedae40f642fdbbe19e4ae5be4a67b3341f0f82445baf17c8dbb6e203a39106a29e6a939bb738717072bfbbc3df513a0f0be86712ef0ba1b612031dfbdcc1f5ea03705261396a8dc07599724391b8df3304543d608bbd84c355b06ac85612a22a99a6bc0dcb67c653075e2c21c2acac958d904bd2f1173ebdc63b1cea777f0fb9ae63df1bdd1c959f4fe3aa5c2c1d447ad47d905f478f4c013d7e84fc5d76b339ae69e06e8b745e2e49fe00d95becdfe00ac58d61a5d496e7f673e5680c28e4df19d90888758fb1557b5d5cfa76ac0fcc81e516ef7b00d7ed7f00dc0ac424a4ab165b4418d9920ddfdbc2c969fcfd65f435664141c934fc1a8fd162d91ae9baaba62cff698aaa6e40bcfebf82292cb9caaa97c959da402506ca5f717a9e37084e0ac48fd1d1280c75c42f008c9aefe655b9f32447148184285ed9532fc94a754f3e2dc9dc8da86e88ede194176cc50c96eeec4bf9bdb74d1b5eb13537ff6f672199d4b30dd91707d3e9bc9a16edd959b2ed2e2b71632526c
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146203);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/25");

  script_cve_id("CVE-2021-1223");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu18635");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-filepolbypass-67DEwMe2");
  script_xref(name:"IAVA", value:"2021-A-0027-S");

  script_name(english:"Cisco Firepower Threat Defense HTTP Detection Engine File Policy Bypass (cisco-sa-snort-filepolbypass-67DEwMe2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Firepower Threat Defense (FTD) Software
running on the remote device is affected by affected by a file policy bypass vulnerability 
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0.0.0', 'fix_ver' : '6.7.0.0'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_summary_snort'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu18635',
  'cmds'     , make_list('show summary')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds  : workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);