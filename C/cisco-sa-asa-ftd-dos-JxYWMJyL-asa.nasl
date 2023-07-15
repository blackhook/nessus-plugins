#TRUSTED 01ab374bccd01b05962c172306329dc47c8795aedcb6d2abcdd25bca0cf1f76dbca9c03e0eece14e3590e516ae7e1086574e58e938e9474cd28d64ef6e590b1615c50eefc73cf10a0c7919ba3e6c8bd66a6c350ffec12c03ee41953fd4283ace1e6d8554365eb7d66c3370859374f9315205e94705c2b769ef493065daa6fc4384e4d76a042b41b934da59831ac91ad9ad5328598e23297a4bcf97e82874d480708e4c26c64164a00e52901e24f3dea2c294b2effb2b5a66e599802b6eb4644584682f88b1d5a25d34ca7e29d45f8b87ac715b76439481d3213bd5d24a5800cd9a6205ead38a4424170b439d7bc795cf98d617e1f55a1fcf47432f22e7795b9c47128a65d283dd8b61e97d8655bc6d5aabe2ae058d6a747de660c914c3746ac012fad8f7d03cea13421fdfb3cfb6b74b5f0a7970244127c625150cf952f08579a4c7576094ab5e3945f0e25f74516bc536083123f6431de86aac98eb5d8bd9c77346f3ebd2aa4bbdd7415b5b02361023e355cdf40826cac0bd57ee8fb9b104aaa84c9f1a3eaf259f33a165d8ea9f8ab23322bfc86179a3463350ad77b9b757b9b144e93dbab69c32eb7431efd11b18310feffe6642c6e18e88896bdad007f31c9724010e7a87d0437f97e657dbc978449754e601ab2fe24f4b7c1264d8dfcf701ebcd52320990cc2d66c2e90d4b32773ad9c6133d4d6b7ceb4d9a7366e813b23
#TRUST-RSA-SHA256 6fc669fc4c13e47ba9a33530f59b121f996a8bf0d5c23fe0ebc49d2014c5786d9257a2bc867d48de1eb8f0c8374488125638f0ef8559c2370b70f14579cbaa3b3c317a54d9b2ce00c914b5c78ac42851869f47595f8dc44095163a80e35a7fa6f3afab82f295a8c9cac91ab558a71f0f2f7c43439dd6808551c122915be154d0641e375c9dd23213c2132a170f0732f6c2397edd10a391b10f4e705154228b1137acae952743ae207a6891a9aec2e2b1f538209290c52d46dbf8098128521408862d25a8ee0f7f74735dbdfdc0549439ab7901e23302b57eb625723bb755f45fb18bbb1b6989e9e6a7828d6ca1e9dca0b55e4bc4d3aead53bde36cd282e18e503714a518b2f29be0c40ad02b82443d288af98ecdd924eb088903cc86bebbaf4ec411ab12a2cfc4b90f4e34832fc2e9efe487e1a857135e38b94fed9a2e688cc5241c1c84a5362b2be47d0e7c23dbefac14cf6fe4ace4f85824ed4bfc29ba890b9a07e9a513bb0300c3256818e0883d895dfc4691107f70ab8286ad05874a9de698530d98eeca9ee84fdfb057ce0cf98940bf99cf484292f0e7197ea02e8666144fb1a0c5be399d4dff0ee06b88fd5efbbb9bfbe376be01c92f093f4d8957b4bcb54c7cc24bbfbc1c403077dc9296e94071ef1a2c0a9c2429372c44c53afb5c1c830b65e6750add95006c584c649a6668945a8275672603fbd5fbdbafd29e77b8
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161882);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-34793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx46296");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-dos-JxYWMJyL");
  script_xref(name:"IAVA", value:"2021-A-0526-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Transparent Mode DoS (cisco-sa-asa-ftd-dos-JxYWMJyL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a denial of service vulnerability. A denial 
of service (DoS) vulnerability exists in the TCP Normalizer. An unauthenticated, remote attacker can exploit this issue, 
via poisoning MAC address tables in adjacent devices and cause a network disruption.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-dos-JxYWMJyL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e81ea8c8");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx46296");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx46296");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(924);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.40'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.24'},
  {'min_ver': '9.13', 'fix_ver': '9.14.2.15'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.15'}
];

var cmd = 'show_firewall_mode';
var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG[cmd];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvx46296',
  'cmds', make_list('show firewall')
);

cisco::check_and_report(
  product_info      : product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges
);
