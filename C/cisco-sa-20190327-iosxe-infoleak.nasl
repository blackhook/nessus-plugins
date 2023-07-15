#TRUSTED 3ac9c4ed779acc9ceb6b0f65f87cf1c40e8e5e7618a9649a5f493079a833a2d53ea075b249528ba3ae9758833b7329a797131775fbd8655c3d46fff8bdec610ac6221bbe93cf626c8229bf24949a5945b814bdae07d3479b6969d16b471a27809a8dc263b4ef0f42420b06b2b577b383ad27a32995325b4389e124fd07fb291af038e96fe4b28536327ef22bbefa55d92ef5ee9f475d5a9a721076da7bdbe0f9ffa8caf121bb4545f49321c6c2394f4e7fd7226945042da51bb54fc6e07390ce274c5342a7b3ca88fe5174ffbe0de9551bdea19c75f2bf449c9baba3aac8ef89e1eeee656f0cff0aed7755ca4b7998559a7957fe588b6de288180c6b63638437c1fa35fc9cb3317312f3a517b4e9690795ed16cef5d9707d49f9869666fbbb57f290ac37d3fd4e712876628f45e510c7d8ac5017da7a269f9b2a19bc6949cbfe43f9095bc23b7f40daec8f72be7775ef02314a08b59e21c2b1ecce91b88d6978bd9f0179757807858528ff8ade66df128c24950e6ce3267a5b8a048862236d7826440dde621ae11638e42dae1121bc0cfdb146994a055d2194ae655dccba68a21866ebb7172d8f789f760aa098193e3401a1eef8955bd817b744454092bebe15ac679442287c6a1d04f1eb4720fda68e98552023229dc03b6c1859825920872108f84365bed1f820cfb0b0565f161c4d1ba8dc6ad02eaf860d086c0392e06180
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126507);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/27");

  script_cve_id("CVE-2019-1761");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj98575");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-ios-infoleak");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Hot Standby Router Protocol Information Leak Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the Hot Standby Router Protocol
    (HSRP) subsystem of Cisco IOS and IOS XE Software could
    allow an unauthenticated, adjacent attacker to receive
    potentially sensitive information from an affected
    device.The vulnerability is due to insufficient memory
    initialization. An attacker could exploit this
    vulnerability by receiving HSRPv2 traffic from an
    adjacent HSRP member. A successful exploit could allow
    the attacker to receive potentially sensitive
    information from the adjacent device. (CVE-2019-1761)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-ios-infoleak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46d52b7a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj98575");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvj98575");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1761");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(665);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.1',
'16.1.2',
'16.1.3',
'16.2.1',
'16.2.2',
'16.3.1',
'16.3.1a',
'16.3.2',
'16.3.3',
'16.3.4',
'16.3.5',
'16.3.5b',
'16.3.6',
'16.3.7',
'16.4.1',
'16.4.2',
'16.4.3',
'16.5.1',
'16.5.1a',
'16.5.1b',
'16.5.2',
'16.5.3',
'16.6.1',
'16.6.2',
'16.6.3',
'16.6.4',
'16.6.4a',
'16.6.4s',
'16.7.1',
'16.7.1a',
'16.7.1b',
'16.7.2',
'16.8.1',
'16.8.1a',
'16.8.1b',
'16.8.1c',
'16.8.1d',
'16.8.1e',
'16.8.1s',
'16.8.2',
'16.8.3',
'16.9.1',
'16.9.1a',
'16.9.1b',
'16.9.1c',
'16.9.1d',
'16.9.1s',
'16.9.2h',
'16.9.3h',
'3.10.0E',
'3.10.0S',
'3.10.0cE',
'3.10.10S',
'3.10.1E',
'3.10.1S',
'3.10.1aE',
'3.10.1sE',
'3.10.2E',
'3.10.2S',
'3.10.2aS',
'3.10.2tS',
'3.10.3S',
'3.10.4S',
'3.10.5S',
'3.10.6S',
'3.10.7S',
'3.10.8S',
'3.10.8aS',
'3.10.9S',
'3.11.0S',
'3.11.1S',
'3.11.2S',
'3.11.3S',
'3.11.4S',
'3.12.0S',
'3.12.0aS',
'3.12.1S',
'3.12.2S',
'3.12.3S',
'3.12.4S',
'3.13.0S',
'3.13.0aS',
'3.13.10S',
'3.13.1S',
'3.13.2S',
'3.13.2aS',
'3.13.3S',
'3.13.4S',
'3.13.5S',
'3.13.5aS',
'3.13.6S',
'3.13.6aS',
'3.13.6bS',
'3.13.7S',
'3.13.7aS',
'3.13.8S',
'3.13.9S',
'3.14.0S',
'3.14.1S',
'3.14.2S',
'3.14.3S',
'3.14.4S',
'3.15.0S',
'3.15.1S',
'3.15.1cS',
'3.15.2S',
'3.15.3S',
'3.15.4S',
'3.16.0S',
'3.16.0aS',
'3.16.0bS',
'3.16.0cS',
'3.16.1S',
'3.16.1aS',
'3.16.2S',
'3.16.2aS',
'3.16.2bS',
'3.16.3S',
'3.16.3aS',
'3.16.4S',
'3.16.4aS',
'3.16.4bS',
'3.16.4cS',
'3.16.4dS',
'3.16.4eS',
'3.16.4gS',
'3.16.5S',
'3.16.5aS',
'3.16.5bS',
'3.16.6S',
'3.16.6bS',
'3.16.7S',
'3.16.7aS',
'3.16.7bS',
'3.16.8S',
'3.17.0S',
'3.17.1S',
'3.17.1aS',
'3.17.2S',
'3.17.3S',
'3.17.4S',
'3.18.0S',
'3.18.0SP',
'3.18.0aS',
'3.18.1S',
'3.18.1SP',
'3.18.1aSP',
'3.18.1bSP',
'3.18.1cSP',
'3.18.1gSP',
'3.18.1hSP',
'3.18.1iSP',
'3.18.2S',
'3.18.2SP',
'3.18.2aSP',
'3.18.3S',
'3.18.3SP',
'3.18.3aSP',
'3.18.3bSP',
'3.18.4S',
'3.18.4SP',
'3.18.5SP',
'3.2.0SG',
'3.2.10SG',
'3.2.11SG',
'3.2.11aSG',
'3.2.1SG',
'3.2.2SG',
'3.2.3SG',
'3.2.4SG',
'3.2.5SG',
'3.2.6SG',
'3.2.7SG',
'3.2.8SG',
'3.2.9SG',
'3.3.0SE',
'3.3.0SG',
'3.3.0SQ',
'3.3.0XO',
'3.3.1SE',
'3.3.1SG',
'3.3.1SQ',
'3.3.1XO',
'3.3.2SE',
'3.3.2SG',
'3.3.2XO',
'3.3.3SE',
'3.3.4SE',
'3.3.5SE',
'3.4.0SG',
'3.4.0SQ',
'3.4.1SG',
'3.4.1SQ',
'3.4.2SG',
'3.4.3SG',
'3.4.4SG',
'3.4.5SG',
'3.4.6SG',
'3.4.7SG',
'3.4.8SG',
'3.5.0E',
'3.5.0SQ',
'3.5.1E',
'3.5.1SQ',
'3.5.2E',
'3.5.2SQ',
'3.5.3E',
'3.5.3SQ',
'3.5.4SQ',
'3.5.5SQ',
'3.5.6SQ',
'3.5.7SQ',
'3.5.8SQ',
'3.6.0E',
'3.6.0aE',
'3.6.0bE',
'3.6.1E',
'3.6.2E',
'3.6.2aE',
'3.6.3E',
'3.6.4E',
'3.6.5E',
'3.6.5aE',
'3.6.5bE',
'3.6.6E',
'3.6.7E',
'3.6.7aE',
'3.6.7bE',
'3.6.8E',
'3.6.9E',
'3.6.9aE',
'3.7.0E',
'3.7.0S',
'3.7.0bS',
'3.7.1E',
'3.7.1S',
'3.7.1aS',
'3.7.2E',
'3.7.2S',
'3.7.2tS',
'3.7.3E',
'3.7.3S',
'3.7.4E',
'3.7.4S',
'3.7.4aS',
'3.7.5E',
'3.7.5S',
'3.7.6S',
'3.7.7S',
'3.7.8S',
'3.8.0E',
'3.8.0S',
'3.8.1E',
'3.8.1S',
'3.8.2E',
'3.8.2S',
'3.8.3E',
'3.8.4E',
'3.8.5E',
'3.8.5aE',
'3.8.6E',
'3.8.7E',
'3.9.0E',
'3.9.0S',
'3.9.0aS',
'3.9.1E',
'3.9.1S',
'3.9.1aS',
'3.9.2E',
'3.9.2S',
'3.9.2bE'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['hsrp_v2'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj98575',
  'cmds'     , make_list('show standby')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
