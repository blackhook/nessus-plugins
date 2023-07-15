#TRUSTED 061678fbebbbbd3d80c1dab3184152c029b3621396e80722f428224aa571f0fec03cf2c84720eeba1ae9478476b736a7f3ffbc5118627ba158f36c3bea46903fa938a1fa9ce45d3a6766c200d94d63905378935b3a518af6c1b2f30cce7be18a434da1eb26f185112dfd93026964ca51a6f67ac470bbe1b3f329846246475cc87bc4381dfad6e9e5014f15f88e625dafe32de89e53ec9d187ba1902a0a973fcf86a75a44a3b789a4cce55d26b6fb8d356319d0e3bd51f2f506405d2d81e20ee143bd67b3dab6baee22c85967fe9065de94fbe41f98c21be546b951e189c251e7dab08900900cc537debcd6fd908af248183b4621d6636608e99bebbc5f474ebff66aaae42113d72458d9362d7efb37defc4b855c27e15add99ed28e8e57fc4b91093a972ce713a25e750098a1c8b9c0eddb839247e0d08ed63f16aba326982d1cdc135584e60de3cb49274f1596df37c3945a7f7f93fb3997ab1a4c9bd3fdb793e21345486f4c93b27ff469d07ec28cdb0868ce63c0af793f4bcef0ee79413bbee1dada5883c8d359c419dacffebfbcac9265ad9d25f7a932a8d5dacdc98479bb33b71ac10bf953fb755b6d7a784364c584f24972f1c48e187a5cc4accd9c46eac87934deacc96663311c3d5c4a68323245e9a22db946bcdcaccffbe0252c7235028faf36cfa8b039699b6cefd614752c3e0f5719c771d64a1faf29b813fb1f0
#TRUST-RSA-SHA256 a37cb5988da23dcc6e155114ca1024e07ef2dad99413c8adaedbfbc2952a91b9f6bff0336d81eb4cddcf06e37807ea4414124dff25e92950e9f785e2ae9f9c0b82263a1596c3ddcc78c65c0c703323cfb71e84e70acfe6773ac8269dd27ef93a6b9a3817a61216e24e2ecfbbaa166522ab1596e105fcf2cbc3cafdd595f227105de38f1b72350065b2d5bcfa6b612fa272ada5e6327b141b6c3704c853390bda80566a97fc4ff7403701269a51b6e98cb72cad489efaa8381afef6d0becf16bb461f600472b3ceb775bcd52ea9d91b24914238b59ffa2885707a9df192a7bdafd7dc09fc7a9cc767b231d471adcc4962e20c405de15170b0aeb58a39a0931e5ae35dee926be154aa8ef688d2946ec5b769bbc2e3b3d1522113fda1a662f59fed77ed087ed0bd895938e02d9449fa871c18003ae0521e80f5831eec1c37692d6c513c7c47817ebb9feb865e76a0a9b4e177af629f8087051bbf42d4aff9d263cf814a99bb8bd47e2450ac9e084c2c158ba58c0e208a3b870c94f321db347277d80ca72e29eba5d21d7e52e17b32052cd0f521f3d80144c2b5091e74c3b4bf103ac0f2f3a760a0d14ce1f7608af3f3a8eff716634eaec57dafaf4e559392bf27934153a0f5d25da6c4af67ae54e401a0617540c5036328096de538f56a514e32a91d02b4cb27b4d8f3185445984e2c45ca5223a70a014b29f89ba94b8097ca0ca9
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161182);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20759");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz92016");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-mgmt-privesc-BMFMUvye");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services Interface Privilege Escalation (cisco-sa-asaftd-mgmt-privesc-BMFMUvye)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web services interface for remote access VPN features of Cisco Firepower Threat Defense 
(FTD) Software could allow an authenticated, but unprivileged, remote attacker to elevate privileges to level 15.

This vulnerability is due to improper separation of authentication and authorization scopes. An attacker could exploit
 this vulnerability by sending crafted HTTPS messages to the web services interface of an affected device. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-mgmt-privesc-BMFMUvye
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f748ef1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz92016");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz92016");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

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
  {'min_ver': '0.0', 'fix_ver': '6.4.0.15'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.2'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.2'},
  {'min_ver': '7.1.0', 'fix_ver': '7.1.0.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ASA_HTTP_and_anyconnect'],
  WORKAROUND_CONFIG['ASA_HTTP_and_webvpn']
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz92016'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
