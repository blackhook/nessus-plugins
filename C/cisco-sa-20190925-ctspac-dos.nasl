#TRUSTED 241a82754be731d324955b4524acf985adfe6ccf76159d85f198c52e11f6be482f64a0038708c87c7d3cafcca267a8ab76ed1e74b1194db2cb5b072ccab102789fd0ef3f1fde4d30b25a270dd1edfce84f0bbecf6e6448c09f46a67126e6fbce11756cccec4baa52a09b9aa76b53d859ee78c8e709c96840e1a62d9cf9b88d08a73a1e8c06437a0610cd24c10848dc2cea73bbb456d34ba3e42b4a2c1a0cf0dfae68b5c6b56120b585bf13cc7b86b45410faa5df5fccb19b849cf8bb81c8c00068a734521a22962807cc9af81ed61c47089c49f885a2f57843b7616478ec885ea97f3fdd3b65a269e310bf82c9753cc35d6a445858fd0cd2010ddd25376fc95c25929443659a4a740e19b8d9038076f50874d230a9887bfd35e0986d6c15e33f1952c29f022a924b1319c90a5b15546243935d18637f8877965e3ca16ea49e7c3f6a68060ae2843366396d8d654bdeb4da0a485312ac8cf878a5db0ac9dc28774b5fcbd3e3e5c111417811cdf46ee2ab785695f1f3f3f3aae985afeb121cd29089973f4a0c3d663fd5cd38930a51989ff31885cb6821c222c9bbe2f1de34cbee4fd82d0db36e07255d3d77487f0b2bb569c1ba6a95ce0d89d3685744ff2b2f471d11748040bf152ed33cb266ad6ed746c393391869856e183e1a0d330334750256c6195d05ade504b6bf6f3345afc7eda8b9150a90e0f068cce60b18b11de718
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129592);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id("CVE-2019-12663");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo79239");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-ctspac-dos");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software TrustSec Protected Access Credential Provisioning DoS (cisco-sa-20190925-ctspac-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service vulnerability. This is
due to improper validation of attributes in RADIUS messages. An attacker can exploit this vulnerability by a sending
malicious RADIUS message whil ethe device is in a specific state, causing the device to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-ctspac-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67bb03a0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo79239");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo79239");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12663");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/07");

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
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1s',
  '16.10.2',
  '16.11.1',
  '16.11.1a',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
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
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
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
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['cts_pacs'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo79239',
  'cmds'     , make_list('show cts pacs')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
