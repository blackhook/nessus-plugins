#TRUSTED a12f54d326b354fdd011666b53a57011f90afa22637e06f38ec7323bbc0ece6dbcbf23efb629990d5147910b9d6c9df15a442896faf26955d729fb798a22e41fdc6874dedda3794d4dc6e413cfa0127331e8119d6644843165ff4e0adc696d703169ad823c880f3cef049f3378c52b81dfa76e283a8aa8733c8edfc1403b8c9835b7c326abaae391dcd22f2164604cb64d2bdd94bac641291bebdf6bffe92ad8fcde59ff269be66ae5e8ad4f45f17738cb01cc32abfc17787fd45f31864511ecb3322bde51772a139cbacb6c276c4326f3776019eb3fb0ce4f86b3de753eb527ea42d35d45ff9fe93d8ddc745fadb3240202f7a6318d314a19f06042d09155c685595f629106c660317f90258c405bfe67063fd738ab2709f4f59d72dfe730d22920f8904c0425c5c777b5d067e4f18a95050a78e1c33994bdb385b5ae25db3f5fac7f96c79c1fae583f7b417542d79baa93febf8f397b5118beddbfdf53d5570e4c452780754c9132c7b351c31f947c3c80c28d09b1174fedd758c9a5e6f62a2192feadcfd078e571d1dba3687fcf2a174ca17c577137a46aa5bc04dd5555407a68b636d62efbb61df5a10b33d52faf3315abf01c8f5c9f65c08cdc4d75ba548b78d2e03a4fbae33dbae525b838c1bf5a119087e15748288d18302c164565816c6f43984af3d138b80e94466c72d13262669a0735afc20f637883d421ca80d8
#TRUST-RSA-SHA256 2720154c76481ea834799f5ca7a70a8832d00cc6e04b2a956b53bad7431c38558e7e23bd858983b03e25e4581557b2ab82688dc6ee24b35c813ec7941f878a8083383c1d3ea6e154213c7d65c64bf9f92e5bd3616fd09d621de6b0dd15ea1cbbb95a431a8bec04d8254c59d581679df527e20ee1635ba60dd5e038d0a87b9e3513da68273e598deaacb60127934118a242b4ee4a357047480b9c55386a2c40e35fc2f05a9c34c6e1ab1a5250334d8c7079a4d64ae9274be0b4cd3f33dcb8830b6c0ac4bda771c504de3d797ee89a58270aeeb21147b304508380c7def36b5eb274bf119d57e2a01f80a77d2f29abdea23c4f7160a8cb6f80a5b5b87b703e4badd26b0fe28421265d527f53bd2f4b9a008c0f1f10df0366a928f8a4c930a7356e5987959bb674f9b90f929f54aae0f481bf8578926fa127a6db15b0a2ff42ed06aa1365a17dde5290c768fd2d9ab21e47f276c1162e7274205a6b03be43e39d00bc9b9d7841edfed9341e3117dafb890d6d28dcd511afb206234cdb7eae7801e8d7d37955fa08504f991490084feccea9ace6bd3d6d2c60ce5ef8a0ed00423b9618f5f221c19aff66ebcb64cf0af8557f1da2df12d882286b14975468fac333552067c4b73f57a47ec6c62e8d00ecf9d165f0f60fd79514155c1040b901b66991fb4ee3c718ad1ac527c5a0d71876d7160d381fed31fec2e947fa38b63acbe4c9
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161868);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20715");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa04461");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-dos-tL4uA4AA");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Firepower Threat Defense Software Remote Access SSL VPN DoS (cisco-sa-asa-dos-tL4uA4AA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the remote access SSL VPN features of Cisco Firepower Threat Defense (FTD) Software could allow an 
unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device.

This vulnerability is due to improper validation of errors that are logged as a result of client connections that are 
made using remote access VPN. An attacker could exploit this vulnerability by sending crafted requests to an affected 
system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-dos-tL4uA4AA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3087735a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa04461");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa04461");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.3.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.2'},
  {'min_ver': '6.7.0', 'fix_ver': '7.0.2'},
  {'min_ver': '7.1.0', 'fix_ver': '7.1.0.1'}
];

var hotfixes = make_array();
var workarounds;
var workaround_params;
var extra;

# Indicates that we've authenticated to an FTD CLI. Required for workaround check, set in
# ssh_get_info2_cisco_firepower.inc. This should always be present.
var is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
# Indicates that we've successfully run "rpm -qa --last" in expert mode to get the list of applied hotfixes. 
var expert = get_kb_item("Host/Cisco/FTD_CLI/1/expert");

# This plugin needs both a workaround and hotfix check. If we can't check either of them, require paranoia to run.
if (!is_ftd_cli || !expert)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
}

# Don't set workarounds or hotfixes if we can't check for these.
if (!is_ftd_cli)
{
    workarounds = make_list();
    workaround_params = make_list();
    extra = 'Note that Nessus was unable to check for workarounds or hotfixes';
}
else
{
  # Workarounds can be checked with just the FTD CLI
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = [
    WORKAROUND_CONFIG['ssl_vpn']
  ];
  var cmds = make_list('show running-config');
  # To check hotfixes, Host/Cisco/FTD_CLI/1/expert should be set to 1
  if (expert)
  {
    hotfixes['6.7.0'] = {'hotfix' : 'Hotfix_AA-6.7.0.4-2', 'ver_compare' : FALSE};
  }
  else
    extra = 'Note that Nessus was unable to check for hotfixes';
}

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa04461',
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:hotfixes
);
