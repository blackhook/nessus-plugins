#TRUSTED 6ed632488b02f7f644085415b1cbe6ae3a4c0b023acec3999141575081ae4aff820eb1db42384beaf7542e10bad6ba03c489349354b5583dc9a854935c103d663279997886643f019ebec122816bbb19db3f956acc561dd9c9fa4792ad1574ec9a3641c9a977b9cb78e4601c88f268fd0d712c55210f62ce2b5fe38e8749ee63c0a971817dcdeb78b976f262f6f6939bc725f3f775b1f847e9d8ddabb43dd1b29b946892aa48718d812a020150a9c7323e8b98fb9ef46629ff54f079a78476eac18b5492373557633f1fb4ddcb8ec1563d9b83074448bd0e8c7303eb482d50e6f51c50088c08d14369cf8f2308078ad72f701a8e06285483a8238777382e6ddb2e4b2ec2a7c74be060ac76fa3bf090ea1e3953bd30218dfbb9a4ea980c45b015bf259f188be12ebb5d2362f605f2702f8bc2e479f1fd63756ed01218e528f198044de07c6dce36f8b050c144e8644b7e689dbbf8cd2301f9dd23218bd45e68e497a31cd3a1f207b3d46c1c7c7f9c8fed8d977472be78ee1098d5af6c7bb10e8c48e9d50208886d2e446f7c7435475b5cff533cedde4fb3322960599fab0e3857708a27fe4ecd1c89142a448fd4c94c0de43e024d2d9ae6a2be6dd11a09f02db7b6fedaec56d5e3a6c16a812abc382e0e5d92cf479524abff0df3f0624f5235c60c125e90c3fbc0e520a1c30ed0597edc88ede0d83bdf053f28e42c2d17b325a7
#TRUST-RSA-SHA256 668b1db72b8b9bedfbe8a903403ff369a8651e0b7f35560486cd3841753b67acb2a3a921bbcde829d9a603d9940eda9752d62c6f3721f01fdc877c9f1fd727aedb7429e8a11549d28959656807c6a79475d23736da872a6c565772bc6d2f3e98b94d72038f9a62ccaedc56f42e8c7d916e995639f25b02526c163d7b77979c03c79529e38d45aad8369df6c7556b3b53f0a250542107a485501549284187443d3700e1026d7e435e1a829d0e0148a6403c6c22e66db0c3fe7f3368b76674c3dca07751dc7885ed0fee25ba5f559f95b6a645b410d67b80152a3dbfbe235c62b0e9677e14a3ed32fe8694da87068b07bef91168f44506a7e6c9b81357762a14d6f77689567b4e1010bb915cb63e02855bf8ac1e3b3cf0d3e90292d90d1174023cacd01f658cf52983e6866389e32ff7108f78df282b30e4d99adbea60b98a196b8eef99d59fec0b90de433126ffde6fde3beeefee61712b5ef034cbc35eca699b33d491ccc52aa0b044839e296d729d9413ebc6a1f58553eee6284fd475182e177c4a12b3b331055254f41276d729ba87e3c1fb543d07bba49672d819fa68d5607c78d9e9b8ebb080f970bc4a39c956c1fe149cc64cfd9976e995e80e3c278307b67791104e98a6406da880264bbbc51063bf2f824e2cff0129d39cf199a403d0800502797a7eb0192c025eba8be752e763bbbb157a3da7fa9bbb6798674cf6f9
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149209);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-1402");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo46649");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-ssl-decrypt-dos-DdyLuK6c");
  script_xref(name:"IAVA", value:"2021-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software SSL Decryption Policy DoS (cisco-sa-ftd-ssl-decrypt-dos-DdyLuK6c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial of service (DoS) vulnerability in
its SSL/TLS handler component due to insufficient validation of of SSL/TLS messages. An unauthenticated, remote attacker 
can exploit this issue to trigger a reload of an affected device causing a DoS condition. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-ssl-decrypt-dos-DdyLuK6c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c673d8e1");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74594");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo46649");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo46649");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1402");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
var is_ASA = get_kb_item('Host/Cisco/ASA');

var model = product_info['model'];
# 3000 Series Industrial Security Appliances (ISAs)
# ASA 5512-X Adaptive Security Appliance
# ASA 5515-X Adaptive Security Appliance
# ASA 5525-X Adaptive Security Appliance
# ASA 5545-X Adaptive Security Appliance
# ASA 5555-X Adaptive Security Appliance
# Firepower 1000 Series
# Firepower 2100 Series
# Firepower Threat Defense Virtual (FTDv)
if (
  model =~ "FTDV" || 
  model =~ "ISA3[0-9]{3}" || 
  (is_ASA && model =~ "ASA55(1[25]|[245]5)-X") || 
  (!is_ASA && model =~ "1[0-9]{3}|21[0-9]{2}") 
)
{
  var workarounds = make_list();
  var workaround_params = make_list();
  var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");

  if (is_ftd_cli)
  {
    workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
    workaround_params = WORKAROUND_CONFIG['ssl-policy-config'];
    var cmds = make_list('show ssl-policy-config');
  }
  else
  {
    if (report_paranoia < 2)
      audit(AUDIT_PARANOID);
    var extra = 'Note that Nessus was unable to check for workarounds';
  }

  var vuln_ranges = [
    {'min_ver': '6.3', 'fix_ver': '6.4.0.12'},
    {'min_ver': '6.5', 'fix_ver': '6.6.4'},
    {'min_ver': '6.7', 'fix_ver': '6.7.0.2'}
  ];

  var reporting = make_array(
    'port'     , 0,
    'severity' , SECURITY_HOLE,
    'version'  , product_info['version'],
    'bug_id'   , 'CSCvo46649',
    'fix'      , 'See vendor advisory'
  );

  if (!empty_or_null(cmds))
    reporting['cmds'] = cmds;

  if (!empty_or_null(extra))
    reporting['extra'] = extra;

  cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_ranges:vuln_ranges
  );
}
else 
{
  audit(AUDIT_HOST_NOT, 'an affected model');
}