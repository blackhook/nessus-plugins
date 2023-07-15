#TRUSTED 6b91a7588e0e3d1a77927cc02b42d01fae2bf123115dc764b281e1036c6edd011fc2c9dbc55f881c73fdcf7c8f097236d2beafb720fcc529f804cf246862d8342248c57b6f58a8a1de143c6f5dcedb0c64df418cff338076672676c11c9317e2599dd17ac9dd472da741c38efc951daec9bdc4e28135a4610e65c7977d0f0b919e7d16e4451b81a52c47794978302d5cc00b372ab0f65d1841b93f948c8ca9243b4eecb9b8f3863496f7fc19e7093f1267d261d08e76a6ad69fc2f8b635f22c4d92395b071900c3c2e011f725c0e83c6bb74be93cdce59ffe61924ba91d764be10582386ebd337521949c27ea2315503f6ff6b801cc8b19bd389d79239f4ecd8568325fff128a6b5c37015ff0029bb3790da7ed419075164aa8258457a5df6ebf184b7a6a00773880c1308f58a4282f499ff41f5d9605117b964a08aa5a2e52ccb74fbdae12ebd9c854491f918029e35301ff529074a6020ca9e197a4bd031910d614117e811444f2d57c0242bf06dc0c3df0646905f0e400a4926c7e484a911a5c378810cf87246df09c6ecd0f87c93902400a1a4d1fe6d2fc0b9ac644d19082464a13058d6d6e167f175377e82fe7e6714d4089bd06f919400880516ed11ac13c28d7fde88f4c21648a06c0a7a0b0063028a13a19b156a58451b7a5c8ee3c28c528d20250f0f2740c68fefb81027ac04a8f849e65bffeb560b8bcd71466e24
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129499);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-1755");
  script_bugtraq_id(107380);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi36824");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-iosxe-cmdinj");

  script_name(english:"Cisco IOS XE Software Command Injection Vulnerability (cisco-sa-20190327-iosxe-cmdinj)");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the Web Services
Management Agent (WSMA) function of Cisco IOS XE Software. The vulnerability allows an authenticated, remote attacker
to execute arbitrary Cisco IOS commands as a privilege level 15 user. The vulnerability occurs because the affected
software improperly sanitizes user-supplied input. An attacker could exploit this vulnerability by submitting crafted
HTTP requests to the targeted application. A successful exploit could allow the attacker to execute arbitrary commands
on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-iosxe-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6535745");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi36824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi36824");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1755");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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
  '3.6.10E',
  '3.2.0JA',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);


workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi36824',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
