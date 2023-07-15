#TRUSTED 94fba2a9476992d54f3268821e11f67cc8461174961049d9f86f63d4de8aca29129b665aafff1ec3a92df93d3806124815cb6b448695a65d5afba5fefb79db76ed0baf519613fe0331a4701407fe707057c1df95d793e0aac904f50dd3ca0f7dd41241e5ac5a1d842708805461def2c00d89dfa43898e7c424a3296327d744749e985f38ea1dcbdce3c5628760df64aedc16d49c5b51a3fe11b53292053786f5383071c02cbf87233d09265ef1c92fad5b4adf3b6aa46a710725a5b6c9a073a5286d8e05227ea0cfe93db456879a5382767458fb95bdcda3979a1afae0567aa720354b02ee26238e878f97d30014f47a303f49012f23b1032111aa950cbfc080b4349b6944fd27cbb0e948a89bcfe2c145ab74e5d4013b615a6d478560c9e5da7f2b2c39cc9bcd88c9a59f45f619811f871a4fd4f11735f53418629cfb2c08dbd691a81349ea5b1641f19ab4a0ddfdc891e050b67b13a9587f0825f32e8a26d2603ad30daef8d332681e8397987599b30f847e856bd86a25b3e28c3a3d405f8e313a88c7dffea1aa4804bc13030ba8b8ebdea41814a2291c9f761728e6f38cfcb9d31386ecd154eb3b1cfd357f121a28a1be10af6b32572da81a01aae4438651b0d0b713a75bf87bda61553ac2a330c8254e4629db2f38e818e609fc2d81c51f31613c1203a60f666197d1b5610e5095e7523045db71e0c5945254410731d4f8
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141372);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2020-3511");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr57760");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-isdn-q931-dos-67eUZBTf");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software ISDN Q.931 DoS (cisco-sa-iosxe-isdn-q931-dos-67eUZBTf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a DoS vulnerability in the ISDN subsystem due to
insufficient input validation when the ISDN Q.931 messages are processed. An unauthenticated, adjacent attacker
could exploit this vulnerability by sending a malicious ISDN Q.931 message to an affected device. A successful
exploit could allow the attacker to cause the process to crash, resulting in a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-isdn-q931-dos-67eUZBTf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2af093d4");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr57760");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr57760");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3511");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4s',
  '16.6.5',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '3.10.0S',
  '3.10.10S',
  '3.10.1S',
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
  '3.16.0cS',
  '3.16.10S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2bS',
  '3.16.3S',
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
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.1S',
  '3.9.2S'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['isdn'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr57760',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
