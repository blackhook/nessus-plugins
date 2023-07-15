#TRUSTED 84914f9d837a16dd7dedfb4c035828c49f488bdd3a4bcb52ba1f1d1581a622fda5a2bb3a3549d2ae4a3e9441374551ac7c1c274912ad12d3b86d3755b89d66ab5fdbff3e1b10bc5b03d39f9520464a65651be57175db3dde58ca8cd6eb7a59a7f51dc1a543506549b4df46fffa5e78d8a9dd5933c6b6678565642e89b2920f5064fb303d8c2b0f853449e063c2f0712ebb3295df5240e481437b01ffe484bacaa35db6cd3621db105cca4029a24519b0c76edbac4aaa687961cfe8fd92d79f9aa30b782903d5fb3c48c615fb05c45d482b4ae6c6b69179eabf45d9b8e34d45c099e116ca40db5244becdc00854d8060569006d0a23c1cd809435cf6aff054f25b5c2bb05a2b14da10c2bb7c4c595dab564e65061339956384ee0fdf41f54e249356e64260af779255a7e808dd0dc743ee827d66f0c3ab9e121eedaa028785a0c62129cfce71ac73bef1351864922729ec8fccb5d99a45d0b1362517d06baceeb1bd420309bad9a6d7a21da1af2aec2f896e1b103d9c8b202d8b5c1cfb8b49f232309d99e7b5fa6deffc824c5e14c2ca9a5ceda831b9f7f2c5808fc82e8aaa15ad1f62447c3585561bf0ee11531541b3e5174551b495c52354c055a435c75eae05d13cff55ea70eea5826aa697ed9936e610df9bd4aa8a5c1c0db163dfff22a3f304f252d1d82b3c2334e9f567ec1f0f3fb12aac531a53a954034e35bb31f3236
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132078);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0164");
  script_bugtraq_id(103553);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd75185");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-sisf");

  script_name(english:"Cisco IOS XE Software Switch Integrated Security Features IPv6 DoS (cisco-sa-20180328-sisf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Switch Integrated Security Features due to incorrect handling of crafted IPv6 packets. An unauthenticated, remote
attacker can exploit this, by sending crafted IPv6 packets to an affected device, to cause an interface queue wedge, a
DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-sisf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcc60cbf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd75185");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvd75185.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0164");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

model = get_kb_item_or_exit('Host/Cisco/IOS-XE/Model');
if (model !~ 'ASR1k' && model !~ 'ASR10[0-9][0-9]' &&  model !~ 'cBR' && model !~ 'CSR10[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'an affected model');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
product_info['version'] = toupper(product_info['version']);

if ('E' >< product_info['version'])
  vuln_ranges = [
    {'min_ver' : '15.2(2)',  'fix_ver' : '15.2(2)E8'},
    {'min_ver' : '15.2(4)',  'fix_ver' : '15.2(4)E6'},
    {'min_ver' : '15.2(6)',  'fix_ver' : '15.2(6)E'},
    {'min_ver' : '3.6',  'fix_ver' : '3.6.8E'},
    {'min_ver' : '3.8',  'fix_ver' : '3.8.6E'}
  ];
else if  ('SY' >< product_info['version'])
  vuln_ranges = [
    {'min_ver' : '15.5',  'fix_ver' : '15.5(1)SY1'}
  ];
else if  ('S' >< product_info['version'])
  vuln_ranges = [
    {'min_ver' : '15.4',  'fix_ver' : '15.4(3)S9'},
    {'min_ver' : '15.5',  'fix_ver' : '15.5(3)S7'},
    {'min_ver' : '3.13',  'fix_ver' : '3.13.9S'},
    {'min_ver' : '3.16',  'fix_ver' : '3.16.7S'}
  ];
else if (product_info['version'] =~ "[^A-Z]")
  vuln_ranges = [
    {'min_ver' : '16.3',  'fix_ver' : '16.3.6'}
  ];
else
  audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd75185'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
