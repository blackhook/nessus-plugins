#TRUSTED 82a313e6140cd356400fcbdce98340c9c2964f142ffc139511c2a9e10b40e10c806da92a8f3578300a5fb0f90504d9eaa0feaabb08a7a5f1856d1288c1deb25c31950e55f84e5a636709a471b4e39ac369f540a436e8717afccc860c0ed2d0071cb615dd180e9ca684d2926e69ab4a8b50a8fbb0bd3ee8a94f08610aa9b843f1c6dbf2464fdb70ea71174eaa6c66f8157831ba393f461954099397a078813417acd716a18cd799b4ba58bb5ae7de39bebc6809098ce87ef0acff518ea3198d72cd568b85ba2d6bbfc1a6c6c1616a3f21de03e88511afaedf62afa955bfade9d866d9f4323bb04e6c4f41117f292499d26b9074e6cf43cd9c188faa8fdb7b7dd48c948cf3031002f44d6322a5e25b5292e822d75af31234e725cc41aa1dc778afa2074c8bb2d7cfd7d11b10354da300e5bbf0563bb97904fe661e98db92f5ae6b2c4b088a3fd04bd40f837d4b8fe3b4ce6992f60f186d5c82fec5f26baf3847a539d65824486a9ff5bd4f7ca2cdb44cde1d5e4f99b6dbca27169df479fc859c73ce30a37afd91b813c33532bd159c8c044384c3a9bf0c8fc26f4533ed2bf2e87cc9a98ad102b0172fb178eb950d09c9975b02057f74bee0a806f7cc5ceb7055e79ed177fbd601b5a95b581e3810e92cffe111fe1bd2b3a39c1e72f18bbad816b44b5c262f5b4fa14ea51ea34889b731047dcc3eb4034bc184547a5b61c3434b7c
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142053);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_cve_id("CVE-2020-3404");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq91055");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-ctbypass-7QHAfHkK");

  script_name(english:"Cisco IOS XE Software Consent Token Bypass (cisco-sa-iosxe-ctbypass-7QHAfHkK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a consent token bypass vulnerability. 
An authenticated, local attacker can exploit this via gaining shell access on an affected device and executing commands 
on the underlying operating system (OS) with root privileges. Please see the included Cisco BIDs and Cisco Security
Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ctbypass-7QHAfHkK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?988a1f23");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq91055");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq91055");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/29");

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

version_list = make_list
(
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
  '16.12.1y'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat' : "transport type persistent (telnet|ssh) input"};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq91055',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
