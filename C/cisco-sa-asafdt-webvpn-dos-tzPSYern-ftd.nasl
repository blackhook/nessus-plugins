#TRUSTED 22ae219060ff1509ec8430614598348bdef94289a683bc85313fea1914c1982d7d72f1e3290e69b96907217e6a5bee7e6e5453164e97391d36e549218b46b6caafcb85a03a4519e016f238df44eadaccec80935011da0abacaeb083955105bd7cf453aebf8818cfa0282712ef6f344bef33b67d17864fac2d57e7e8efd673b14bce99765d96b8159e326d6e7fb3663cf4143475ac6930c030331bcf20661905bee7f7556fd076064c4d30583900c30efee3f71a9c7974a58a2ab57433286525f249b88bab2b4889ad25127643ee76a8132aa2479fd1fcecfe2ba37707ef2c876c23f58aa960cbd8762f54a690a716301aa964a0dd654d6d1d9404705dad97d04aa8b04f223757187b93fedb6ef02d9678c4bfd160890aa60048380d0b8393a42dca4a9b432fcbb8908e4648cccaa4e8bf414c98e69c99c742030b0aa5e5fe6613cc3f78bfccac80ff7bfadf5f5100f88042b30d255f962098562c64a0d20e35610da0264b8d74de307124baa66cbbe26a0d1c4e9d3b4acbc9fd4fbe9849d67d01449def99d2c50b6ab785aabc80999a5acfca2215c718594d32aa9dc315af0748858eb0a6d72d5af43567690ba34042df63ff6b778016faf8331cb4c1149cfe19d2ad7b2ac24633e4d8be46121a48caf5c3ae3127ded0a70093a136ea4cf68b010226f6a50481b7a3a1d48ba87f048da3aa4532908af933c28ed26d8eedf5799
#TRUST-RSA-SHA256 0901d31a46fbd8c176028e0a39a95e5502385ebb0d777cf80e223c5318e8d36f91c4f1586c46fc120950569086c99409a9e13bf8112c1230d37fbdef675774e0be751a60dc56612833b769b866d96836e5b2b9db01b3420625e07149d5c61954ddc2155566ff8578939f065b88b97271324d72df8f541ed6834d01bb87fc89d1e63496d6b8767d0477e64c920bcf3ce698fd96d15f6d6469a2f756388bc98330d9462d88ca492454db3ec5502d851e81eeee7b743e75b6f41ffc25dac2374840474d619efa064fef67c2a906b2ce6be5815c8179afd0165ad9d49cbd516da55550ec9df6d87cefc865a9dee862d43f3c08a77d3eacbeb809b142744c33aade662f374f0b74756e1de7a3e67230d5f4f4197556dcfc7b435d7cb3e0bd357739c9c126781f281543862b348e33a8330b19981b239a9d71431b1118e31c14ef1354396b780e88465f976d41afa34757662b14f1e5c8e14b3196986854cae6b9343707b5f3e8ef1234df900e86050d73e4cac32debaa68ad21d51eec7057736dd45682cbc40be67c56ca7d5b5a615316b7bb34a0cd3b2f81bcf1544dff5192d0ad079050e711e0b5d73f440a39ae7ec2a3895c3d54a742a9f988e86202f1284759b49b6a25b39e62160840e3728228844eaaea215555350244b50e06e5e9d9106b011e88793da543e642fc9dd73a996f72dd8b0652f176bc71a993a503388970ad73
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161501);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20745");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz70595");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asafdt-webvpn-dos-tzPSYern");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services Interface DoS (cisco-sa-asafdt-webvpn-dos-tzPSYern)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web services interface for remote access VPN features of Cisco Firepower Threat Defense (FTD)
 Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.

This vulnerability is due to improper input validation when parsing HTTPS requests. An attacker could exploit this 
vulnerability by sending a crafted HTTPS request to an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
 number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asafdt-webvpn-dos-tzPSYern
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebbed325");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz70595");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz70595");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/25");

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

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.1'},
  {'min_ver': '6.7.0', 'fix_ver': '7.0.2'}
];

# Indicates that we've successfully run "rpm -qa --last" in expert mode to get the list of applied hotfixes.
var expert = get_kb_item("Host/Cisco/FTD_CLI/1/expert");
var hotfixes = make_array();
# This plugin needs a hotfix check. If we havent successfully run expert to gather these, we should require paranoia.
if (!expert)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  var extra = 'Note that Nessus was unable to check for hotfixes';
}
else
{
  # For 6.5.0, advisory specifies the hotfix name "and later", so ver_compare is TRUE
  hotfixes['6.7.0'] = {'hotfix' : 'Hotfix_AA-6.7.0.4-2', 'ver_compare' : TRUE};
}

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
   WORKAROUND_CONFIG['anyconnect_client_services'],
   WORKAROUND_CONFIG['ssl_vpn']
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz70595',
  'cmds'    , make_list('show running-config'),
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:hotfixes
);
