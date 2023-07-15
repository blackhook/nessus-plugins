#TRUSTED 692910cdeadc2d74c3c0a3790b6868325578004fa47ebbacc209cac957437384ba17dc8c3c348cfb800ebd0651318219f5a21948de13252d14da10456b0523c827c6a0ba9646dda78b9dcc8737ee14e49f90b05b20bde1fd4d13e8cf0bf3d3fa49d74fee617179ddcc7e780cb4a881609b24fdd8c66aa9765ee9471eaf348c55c5fec22a28e12ad27254daac4ecbee0e24e03d5bd4c00522e141bc50b4a4f7be36641451486d612027e5f221baeec46e9483e54b7cbd4b474c784642c7e70db27c74f92393142422833d8ebfeaa7d526bcd6876a6c184ffc5cf0a345cd1de14ec9a65da9b5b2cfe559474c76b793de7ec6d40dacac526af70475d63a1907a8495a15d9a171f2d3e5b07d66cfbf3bd6629fae3c3e7e9e7df0dccc9a426151593ead1044a578d005ea6877c32c9c5e429298dce18c79888b17ab0e1b7bd77d504d93ac69e292db453d2f0faac11073c86ee9db55e91e76e7e9b2e09fa30430664f64283bc7a8a98e501f2d87efcd830146f6773da562b330db8d4fc2a07551fc7feea739bdd75a15aedac21dcd71fb6466452842a74533491697e86ec1453b178943a34ff323c4232ac369198f07c96a3e1ecb471af05085a7898f5d09f068375fbfc3bf7ccdb43723fd3275ec70f4b847466af48021fefad07e875dc61298be9f731d05bc8671bbd7a7c8394db03a23bcc214b75cffc4a817afd911cf3e6b6446
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141115);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_cve_id("CVE-2020-3503");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr50414");
  script_xref(name:"CISCO-SA", value:"cisco-sa-unauth-file-access-eBTWkKVW");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Guest Shell Unauthorized File System Access (cisco-sa-unauth-file-access-eBTWkKVW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an unauthorized file system access 
vulnerability in its guest shell component due to insufficient file system permissions. An authenticated, local 
attacker could exploit this, to view or modify restricted information or configurations that are normally not 
accessible to system administrators.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-unauth-file-access-eBTWkKVW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?366d7b81");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr50414");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr50414");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

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

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
version_list = make_list('16.12.1y', '16.12.3', '16.12.3a');

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['iosxe_guest_shell_enabled'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr50414',
  'cmds'     , make_list('show app-hosting detail appid guestshell')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
