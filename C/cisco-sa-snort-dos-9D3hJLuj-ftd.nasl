#TRUSTED 7e4e1580ee35ec8b62b63693c8d5d119d64dd7bfea88f0f1ed683e3156028632467fc69964fad377a590d663b360fc57bd0b06ff7537f3a217ab13ecd327929ff94c0cecb84ecbf4d5bf209b34214a11d8cb313166b220c5553849059e1dc59f5f171ed036e9d29c3db36f097ca45990162d774c09f47f4ceb2b88ae3e6f4e94d6423494706c6e00f80e2510a7cd4a954d339053f63d4dfef7879aa29509fa897f019a11c10e7720edb47747cf03a855818ffced53701d6e5c62a502b7296a361a6a245c9169f2fd3c8d66b99ba05efb7b0aa541b772f3d1357ddb252670b66502ba5aa329af21b43a5e250858b5b62d11aa8770b5fb68d5f71ccc08736af0fd441fc6ac938b5e26aad84cb60661958053d851849900554750cddaff544a0723236ecc9b0d9a1625dd6c183dcb9ff763089758dae0776a0b4ca3c758852be281911e280364f5c09b3bc8e28e202a160ce4fa3f672cc3416e548be4eae10c809ce4882d93237342ee75f117d12c410896a66f14414794ea0047d56f38a0db73079d6c8d42dcd0974b35f407a425cbc0d31e4bd75bd2538c3bf7e0a98405126001a46e5173894dc6d4faa6c3ae17f396d61f3720c1a8707ca8e0e61ce4f2dd2968c8e167aeb26e29adeb67a684329ec0ae275389a5e630f0d3aa4f8d65a5a2ddc3a8b81f4b111ba56befaf9a66cd0c962b136cb3811c8f15d76e19b9e5e916a2ab
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157157);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/28");

  script_cve_id("CVE-2022-20685");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz25197");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz27235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz34380");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz79589");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-dos-9D3hJLuj");
  script_xref(name:"IAVA", value:"2022-A-0049");

  script_name(english:"Cisco Firepower Threat Defense Snort Modbus DoS (cisco-sa-snort-dos-9D3hJLuj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial of service (DoS) vulnerability in 
its Snort Modbus component due to an integer overflow. An unauthenticated, remote attacker can exploit this issue to 
cause the Snort process to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-dos-9D3hJLuj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fad84ef");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz25197");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz27235");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz34380");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz79589");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz25197, CSCvz27235, CSCvz34380, CSCvz79589");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_ver': '6.7.0', 'fix_ver': '7.0.1'}
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz25197, CSCvz27235, CSCvz34380, CSCvz79589'
);

var workarounds = [];
var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');
 
  reporting['extra'] = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  var workaround_params = [WORKAROUND_CONFIG['utd_enabled']];
  reporting['cmds'] = ['show utd engine standard status'];
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
