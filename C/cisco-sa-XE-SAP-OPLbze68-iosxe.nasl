#TRUSTED 523c1f88be8d96702125b45c9bb94f025e8c34c70d07a31853ef4e9cc3932f75bd40b170047621f2df819164ef55c1cc8ee81a52496e0cd79643717ff7a408b24cb962710afc28420737c0f1146ba8fdabf396a6cfcdc45fcce62c409b27706c26d7315b36db790ca6da099efdbea72dac6e2acec470a41d4a8a97c3a4e104444e5dc7b97af14a8bcb53a46862c8ff9d111d1ac33e7b6adb9e1d80d27d65e38e0e9cf3b50ffc46b0cbf9c9ade0e73459ca9fe16a317ec38e9881830db90447898b9a91a290e31730edb0bd044f92eb8a92be804934a03513c40e2740061fa40e01ff93cde1f8bc1abc405051be169d3a1f93d65c1a73bdd5569bf4a867ff9c586faa92b4df1f8a2f97fcd5e3da693b3115f3daf655df450ac98163a40607db0c8f2779698580d1434c5db5a54c158c2cfd181aadf082610e590fde2e3181bf215292afce29f6215e829bb8ed9704579021f69c8a29f2faafd7766dab5661e1c7186087529804501bb01388b0b2c8d56d14f178f3d6741d517bc96ab6f87cae8efce8489e4315dc625b2d25d2095e85b6cd1fc7d372a8abaad72e8551c63bc7d2e9afdc4b4df59067c47fc07092a2fe786fcd63ddc37c64d94a6740e785073ca48d4d445766a91165554ce776ca8c5ac4826f023eb60dc3a2843514dfb677ea98babf6ce8e78c023d6b3f3eaa698dfe0f4f6f66ab532a9adbe44bbd1f2c3338f8
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148220);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-1392");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu58224");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-SAP-OPLbze68");

  script_name(english:"Cisco IOS XE Software Common Industrial Protocol Privilege Escalation (cisco-sa-XE-SAP-OPLbze68)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the CLI command permissions of Cisco IOS XE Software could allow an authenticated, local attacker
to retrieve the password for Common Industrial Protocol (CIP) and then remotely configure the device as an
administrative user. This vulnerability exists because incorrect permissions are associated with the show cip security
CLI command. An attacker could exploit this vulnerability by issuing the command to retrieve the password for CIP on an
affected device. A successful exploit could allow the attacker to reconfigure the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-SAP-OPLbze68
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5e5f5d9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu58224");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu58224");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(522);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.6.5bE',
  '3.7.4E',
  '3.7.5E',
  '16.9.1',
  '16.9.1d',
  '16.10.1',
  '16.10.1e',
  '16.11.1',
  '16.11.1a',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['cip_enabled']
);

reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvu58224',
  'cmds'     , make_list('show cip status', 'show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
