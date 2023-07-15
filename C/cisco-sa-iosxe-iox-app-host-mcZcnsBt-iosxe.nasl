#TRUSTED 8ae1bf0a932c2fd49ace3df9f12a29b29e5e64145c4e5313a3dd45261d3a922af0405daf9987d0c070047bbacf4cac81c3bfb71fa90bb81df6774dea96f70eeaa0544cff192992f59ff0f8101324f4d31bc727026bf349a0046f5d883e500a1fe8a2ae01cd914099644c376ea907f7072e8fa72e13b44bfabe4715a2fad8c532c3030a79c2fae3954d31eeeeff7576b573ed96a6de87ae136c7b813e614f2ac61f2582fea7565ae8510bd6ff27d21650f48752e48264a96a51259ae8896c4843956ce9b27cb9ff2f20443cf22a5e31b0311961673bbe15138bcf9d265e5a616211fce840247bc21dd7ee68bb2329973fb76a791d0cd42a30252fc6b4974bf77e016dd323b285b95dfc6e7f7965c305c2a5dc35cc827f267d4aaf3761c4d065aac0939bd897e34bc33a02bd0eb64b275d060de8a8b452406c1860c91297ef15c0374a1653f9e37caad4d7ac599e9c935fb534a3bfd7aaaf57f940cc2c728205eba12d6a7726bc8980369fd36c74d05fc05f71b32c466bc7e7e9247cb4d3642a440de57c0555f601ec7be7303b649867c102657f7d2458eb3be2041cbc392d4c3faedd41c23698eb5203feea9ade7f6c5f95ba727e0467fbb7f21a9e9b0b9165f9141863a5c63dfd4bcb9e6be24a129af0085261631346dae2a60d2cfe053b0e3652eb2488c884d5d6756ea95a4b423f7e1fa6ad28f30db66d577dd892f3e67bac
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142891);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3393");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr56862");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr69240");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-iox-app-host-mcZcnsBt");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software IOx Application Hosting Privilege Escalation (cisco-sa-iosxe-iox-app-host-mcZcnsBt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a privilege escalation vulnerability in
the application-hosting subsystem due to incomplete input validation of the user payload of CLI commands and improper
role-based access control when commands are issued at the command line within the application-hosting subsystem. An
authenticated, local attacker could exploit this vulnerability by using a CLI command with crafted user input. A
successful exploit could allow the lower-privileged attacker to execute arbitrary CLI commands with root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-iox-app-host-mcZcnsBt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?110f3339");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr56862");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr69240");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr56862, CSCvr69240");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
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

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['iox_app-hosting_appid_running']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr56862, CSCvr69240',
  'cmds'     , make_list('show running-config | include app-hosting appid', 'show app-hosting list')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:vuln_versions
);
