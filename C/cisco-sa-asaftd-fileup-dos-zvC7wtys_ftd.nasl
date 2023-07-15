#TRUSTED 4fce235f040046f14db3fa63f471e048549cc99d799fe3b25d6dbc067adf915c53a404b77607a534fb7223ff43718422c133092a8901547b6e7dca512f802a045074f0fc4693d0d63e91ff29939d0bf364f633594829930fd48e037d48fb15abb57a9488d8ab850d8bfcccf976167b893d5bb0c216a422d92054b30f5b010ca205d4ef1afcbae3aa59555afacb56b916b2382b03b4a0a25c558ba6f650a408c89fee22e8f850f8ab63bc776bfd14b9af98263f4fd11772ed53b99256b24948a6e0a82e7b894cb86617e39a378078b8726919a14e04b3a20eb5f3451d436fe4f27e5ed0923e73d323c64d071fafd91d694646a00fd8076199f5b540f4fb22a05d5cf900a30f0862524d096279a1dd0ad6eda07e6e838ae04e430397463028c6229dc2727fcd91411cc174a606d0b0dbdb6bfea7737a51424572184bf651220e0c41ecf7969aed464d520cde3d7903705bc9a5f11fba421c0958a424d566a5c35704250b207a340f0e97096b7be39560c82b67e91a9498a96da6536f76a3030515ca193da209d4f620a169d63da180383bb50c189128df7c8edcd833394b56bf6a8f99ab3e7645ad76c135aaa2f6fd83f92559cb07327025fbce7eeb6a6e02a80a85b62e2a2fe1a1947e8a7886fb5c68d6d584184ed279f7c66bb3c96f0a53ccf254410a9d7755a3b38381f667a17e1972725d606b4d501cbf80dc577c1256fa7b
#TRUST-RSA-SHA256 1df77a8b766103aea892e7fd4e90876b98fc1f58da824808dc82bbd5aed68897bc427d0209b57c7d931bcc7bdef3878f85728c270039fcbf628a12687b1b80fa1a272124f34c6f12aeaf38d34945b71e683b4db89e70c7d88753b7923874d375aa2f6b5b0379eaea6609ba4c13dce38775b1378476b810f346ec44a687bf40f05eeb0361af0c041e139a188bb89ee0c9925623795d6be82b3aae831dbfa0fbd809fe0a7916403ad292b289587a7e6f29c02e7b6e6e19db7759114104a4fed1912d09e08a80bebda205b166ecf52d87d989304e90655f2afd148d6ca1771255b601c2ba25047d02bd935c03830c9728d93edbf36a97b3f28131192d9ff0df531d3740fcfcb38784c3a5a09734adad7f4bea3f01a51c9edfab280be35e2f79d527e76da2a3504458e25c2fa43336bb88d5140095b06d2484ed87e0f868c304acde0d3038fe159794c60cb6a5c1e52c182a65af89b67fc7d85aab4f443b02a2c91d436cba5a2649189e6a34327c28fb563329b2513d46aaa588c49940de72ab7377af313a05fe90c8fcf55a484e5df662bbc5766c7dfc5a9339389932998e96e9f97d429547f2177908e60c7413d1faccabf70e64a82d1cc8978b3c19da761013f4eccdf918b3ed6622221580458c94d538c229d03a0d7b57c814f5919bdb96abb35b8148d121c9664450b3dcb529a348afdaa057535d4b83e4d3b3c0759c56f58f
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152674);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3436");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt60190");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-fileup-dos-zvC7wtys");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services File Upload DoS (cisco-sa-asaftd-fileup-dos-zvC7wtys)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability in
the web services interface that allows an unauthenticated, remote attacker to upload arbitrary-sized files to specific
folders on an affected device, which could lead to an unexpected device reload. The vulnerability exists because the
affected software does not efficiently handle the writing of large files to specific folders on the local file system.
An attacker could exploit this vulnerability by uploading files to those specific folders. A successful exploit could
allow the attacker to write a file that triggers a watchdog timeout, which would cause the device to unexpectedly
reload, causing a denial of service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-fileup-dos-zvC7wtys
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?565ae2af");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt60190");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt60190");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3436");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
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

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.4', 'fix_ver': '6.4.0.10'},
  {'min_ver': '6.5', 'fix_ver': '6.5.0.5'},
  {'min_ver': '6.6', 'fix_ver': '6.6.1'}
];

var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");

var workarounds = make_list();

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');
    
  var extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['anyconnect_client_services'], CISCO_WORKAROUNDS['ssl_vpn']);
  var cmds = make_list('show running-config');
}


var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt60190',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
