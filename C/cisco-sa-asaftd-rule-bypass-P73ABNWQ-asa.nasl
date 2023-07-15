#TRUSTED 21c3d2ee3c02c1a47b92937c32500430780f01a77262f14748b484eb34c44c1d8a7fcada265ef737e9f2a499bafa80f4efc6287184a853ce276313e2d252aa57c3f5cb640d484fe1ced72fc613e23b7febf48dc9d6487e5cd3b9c3a8489d47a13b319378e0242683375bd43adf5e282885c59e8d8b40e342a6fa11660b081d81b884cfd3cd6b1c8fa211331762cb00b28329b1fe0984a44e644a92422731946cfc65ba33b1fe2f7924bae4152e71c9d8363652bb6f9ea0c74a485486b46b1ef580cf2148514dd28858ddedbfefbc3db2173e71608e27707dba5ca78d723f0be9a047cafeb17b4d6b1814e873a1b0b9b9ad7fa056d2b5807e29eb9e57bb9fa858b66f917a2af3947e40a1172aaef6e854bd068166af8b971c0df624c798d1f124875312205ab2a332f114197eb4e40668b3fb3674db68338143df5b863cf19db811672330c70e087c9f6eecc798d516cee41e5b12f2fec28cf12bb3aa7f71625f67c52c86ef8640965718fddc2b134b58b5a0e0ea21d236d61b31c0e6b64fd14a7fa7ad77a439f8e0174f77731c1aa3200dde9d50555e2ce7f2cbbfe8f912c17a7bf6855afd4eec2dd2a5f074b49b3bd008d28b7f05eaf7c4d27d8556fb06e278da8ab4b66c451aeec110afd9d7d6caff3dfa47d71bf42dc45bea0115baa125e06a5456dcc47c2cd4697831b08251086f4a5e71c2a3904740b22989111c11854b
#TRUST-RSA-SHA256 167420122e93da1ed3ecf60a2fd801cfef13b5fff679ba66d9cfb0b209ccf86552c3bd212acc54867b18dcf419bf58f906bd5cb7021ecfa8884265a79c53583e6b399985d6273e13ebead8a8c8257a0aa80e46d79852376b797d5a5edae61bede526dc2ad0b7d1e5340543a6d23faa06bf272d2e453b11f99e5b5dc3b289f8a646eafd92ef275d78ae1034c67e55fe68d8bb083167c6d478bf0491e6ca71f3e818dae317b0601194a9fc60952e38f65badc8f66c1558ef91635200f4159ec97a4dc617e3fad80782046261dbe0111c11862a848d07cf8974cec122318ecb6ddd60981d6a16db196be9e5ba77163534fc9584e5efd0de1ac2b138f31e5e0f442bf93ff89d4247df82d6e1f202e68893b247efa7677f4706ca398a28320b2a3e585809139f97c49e16fbf0f9a27a70f60a0632788604b22633d94bd5ffebd6c5c4554e08ab372a27bc9bff8be36e0b0b6587d8a390caea97e8b581df207f8c85a12e200d523bb0e635488c5c99df57152b548bdd9269135c0311230a301d07be775ece795e624980a34e08e0b03e36435f350443c169798fe3da29b1ef8d005ddf098e712cd7ce79ceff83895e37f3cd410a6b731e0755ee3d67cd65e2dceaaae3e207c770cdff26c3bccb541a63463aa9aeb3c9104d3379e02addf02dfdfd648bbea6744e94e0011d085f933b878a6c683a95bad9f9d06c8691d0b40a0e52e600
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160403);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3578");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu75615");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-rule-bypass-P73ABNWQ");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Software WebVPN Portal Access Rule Bypass (cisco-sa-asaftd-rule-bypass-P73ABNWQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-asaftd-rule-bypass-P73ABNWQ)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance Software is affected by a vulnerability. 
This vulnerability could allow an unauthenticated, remote attacker to bypass a configured access rule and access parts 
of the WebVPN portal that are supposed to be blocked. The vulnerability is due to insufficient validation of URLs when
portal access rules are configured. An attacker could exploit this vulnerability by accessing certain URLs on the 
affected device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-rule-bypass-P73ABNWQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b29a97cf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu75615");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu75615");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3578");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

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
  {'min_ver': '0.0', 'fix_ver': '9.6.4.45'},
  {'min_ver': '9.6', 'fix_ver': '9.6.4.45'},
  {'min_ver': '9.7', 'fix_ver': '9.8.4.26'},
  {'min_ver': '9.8', 'fix_ver': '9.8.4.26'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.80'},
  {'min_ver': '9.10', 'fix_ver': '9.10.1.44'},
  {'min_ver': '9.12', 'fix_ver': '9.12.4.4'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.13'},
  {'min_ver': '9.14', 'fix_ver': '9.14.1.19'}
];  

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['portal_access_rule'],
  WORKAROUND_CONFIG['anyconnect_or_ssl'],
  {'require_all_generic_workarounds': TRUE}
];  

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu75615',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
