#TRUSTED 2347f13031aadf21496adf3d957752d1bde3a00e3d13c02d4b7d7ec7dc6f8cbddbf7e4c5c90dd9ecc74636b4ccca2cc683be4aec622384ef3a8d7cbfec2569bf03eeaaa7c5fad43fe63969bf9a19fa527f8a03ffa64a13f0febf139882e73e438da8d50d8c7bed6f580a10767a111bb3577ab7ff964263367917969abb5a1289eabc6f72651efb036b6c6836df1790895f5e25c91048b4220210032634e2667756d781dd6f351b36d3ef15acffa75255a72330c5ca7a3833a290355cc183ce51c347675e3f88ad3bb99e592342974c473da5a49b32dd33c9f1f12e298ec8cd7d35c1c5afdfe85a75c9ecff9b5bc1c37c41cbbb50c994d6694c58cf5f6ece8bbbc289ca06f4d1e6a5e288c516a74f481304ad9a742fd50f4330c861fd245a7af6be44e2611b281ef31f93f9f589ad3c90299b9a7e8216ec9c2148b8a36263fda2544a3b9bb300e518494c3ca797dee3abca6860b769b902861c442684e0729221b2e331c76da73d06f869f1c5273f478ace7a9921fb11df8c2b575a8bebfd9067683a0fcee4e31d7de62c04fd3cd505e17c2ee2fd8311c4c16786a4ffda7706dc094d0795f231be310d954460dee7d84ae55439b6957e23b4bfc59b328dea0feb8439202eac78af575e4ee6e037194fa783cafa3f87ca9fce24a3713310b44233a457197b64a2c428f35db201f92cd03a9329c38f1c63292aa45373b68254584e
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141114);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3141", "CVE-2020-3425");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs40347");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu90974");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-webui-priv-esc-K8zvEWM");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Privilege Escalation Multiple Vulnerabilities (cisco-sa-ios-webui-priv-esc-K8zvEWM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based user interface (web UI) of Cisco IOS XE Software could allow an authenticated, remote
attacker to elevate their privileges on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-webui-priv-esc-K8zvEWM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14445280");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs40347");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu90974");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs40347, CSCvu90974");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3425");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 532);

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

version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
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
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
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
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
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
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1t',
  '17.2.1v'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs40347, CSCvu90974',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
