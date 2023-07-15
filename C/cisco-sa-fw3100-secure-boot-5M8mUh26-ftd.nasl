#TRUSTED 4c4655b2c823fa2fe67d605f63a3e8d62623487877ef8a85d30cc7365695184b14df862bcabf86f3f22876f5f31ff83b24f5d50f325a2b54b8508f3566eb37907fb16c4885870c41382e6905e40ad9f58cdab756c07a742f816e3bba5bf0bec2196f3cc31329943121b10db271c161604767ed418f6d52a1ccc6dfd875a22169137cd66305c1841dee85671f5e2b9a3489b003fbbe1552165a74d8afd2dd44d1e7920abe624019743388a32e8df9cf1f69e697ab7d88fd4839f2a075ad9a80e630c7b8d906e1b508f2cedabeefcf0c50e4ddcb1a181b0980cc3aed7ee6f9d296424c5449a233ab0d993805d1b36a4989778b05df717e3551ba85556db3d67c991ab8d9f7bccd47993a98c353d9f196d20458b72054827e62c755ef8ffe3f43b7603de94174b3979f27312c278e1f08287afeb66ff302216130dd8374c88e4d2a49b8ba27e013707697a645ecc1422f92ae8eaf016f8b201fd62b715c8d8733bf40f45027836c029f6c3a1ae5b6fc7cf3651a754d2fe6e34839c5229fc07c2e9a86e6d2e2049ca572d64564ccdea53f728fb949a38f6609e12c863d677795490fbd48fbeedbea5968bdae841c964f38f4e44e3358eadd7345c8e9d2b9a2ae0fffb6926f5f8d606e904c14d6ac010bb7a4565a57c7dc4508abb8a3df0e37abf3921b9a3e3d506eb1ec6e1251d1bc11a8424fa9a662a5f6bc66b3f910e81c41fb40
#TRUST-RSA-SHA256 6a83fce9d2a96d9cec0d98af435989ef0eec457ebb09b0ff4dac4e89cc5f1a8f5e49be80853ba2f555fe27de645ec333bf1f0af6d4ac71a3161a0a5698c5f98403f101f51586c7b3091d012dc7a5d8b43901477f006be69d014354349a36289791c49241d25477dbdeff7b5571fad2ba89005a2e63008668ce2b555e0f1564d193c0aa0930fa044421841ed02d750767ddb85bff875409c389ff3d6d621b5bef49d3798f2f6fc471f31daae8e945a40aa3b5f734e3a7fc37445b14ca6d93f324370c4a4b22d52f16fc637a8004faa5f83a0ee8e7b93e98a6cb336e879b38aee37ecfcfb472ff402efd01693cdfa621487efa214d604b043b9a3e84fa779bf6495b38b0d7e3f8fc37def3567b0221ed736db0c0cb2328edaef7d4658a03275ca04e05c44e8e6bd74c8e645f975ed6362df84aeada6eb50d78df01511e39215e11873b6f1814b5e8897d501b0d01d9b8e3fa8a8c122cd4aedf6aa9478e90c5cabcadad079291e3061fda9f5f0fc5a6638148b179b70bc525ef32f6c657de3f2c5ed80da6d3e3de19f8282c6c37adc5023a0b62694f1853530f33dc555869b240659f57f13393bc0ca630ef577131a74dae527fc6d4dccf9581168ac41611f31528e570bb9434d5ec61998ad4ea20d9088c46d1f2b1c8d0eb6f1c36367aad38efb04fceb5940803bdbb602e26a21d1188c50ce988f35c222fde79abb1404388efa5
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168050);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20826");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb08411");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fw3100-secure-boot-5M8mUh26");
  script_xref(name:"IAVA", value:"2022-A-0487-S");

  script_name(english:"Cisco Secure Firewall 3100 Series Secure Boot Bypass (cisco-sa-fw3100-secure-boot-5M8mUh26)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability in the secure boot
implementation of Cisco Secure Firewalls 3100 Series that are running Cisco Adaptive Security Appliance (ASA)
Software or Cisco Firepower Threat Defense (FTD) . A logic error in the boot process could allow an unauthenticated
attacker with physical access to the device to bypass the secure boot functionality by executing persistent code at
boot time to break the chain of trust.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fw3100-secure-boot-5M8mUh26
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61519c49");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb08411");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb08411");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20826");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(501);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/22");

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

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '7.1', 'fix_ver': '7.1.0.2'},
  {'min_ver': '7.2', 'fix_ver': '7.2.1'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwb08411',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
