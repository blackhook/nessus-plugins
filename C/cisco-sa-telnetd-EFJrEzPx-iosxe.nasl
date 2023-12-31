#TRUSTED 235abe40690628d8ef6b6bb1c8a71758591dff302dbd966b59ac5dd230268a510dff19c53b0351afc30687c1ea9feace83a5dd5f70ec55ba5d14086bde9818614dec056394a700138763a0ecc78f3a16e87c3096cc8cf89e6b100f8d19146adbd15005b6954cbb5c8d1fb20058b703565d6528e25710723abb6c364ba6acac6c02e784fe6a071811db49e8a17eb4b9b2339a8dafaacf5e46765230095261a26145bf37a3b98840c43f4c93f46946cc6c9522dc4f5f0d5005cfb3a7671bc3962590f82d660acc55fb7743fff295d40d3dcf9f881c94a023b244ca65fb162f884a2f3cdca28aa7fd69fed0f783d25a425a47ee6f594d2d2d7f97e4e8b185cd04f85c78c65508e02ae95980df719353b828044f40f3de7852e88a7bf8beb5b0d460c0ab68f393a2d178cebe04fcc6ae8f5e8ce941aac54fce63837c81020cfc367da02bed4c83b805f9e5bb59538067c5b0195a4828214d374921b906341b697b918d4c45ffc77115ca9aadc0da9c5baad2234aea41a98748c932c759fdb4c64100c1ad3ab4f9fb093304540b26397c1a0ee5ff77d752b0c425d72425caf1372028adbccb3c4b56630a993b7c91de3cd9238407b9d2f22ad38361f96291a887e11c03f14be59818055ba0bda6b9fafb4cf92424b26a129e5ef0dd8bf47c9d1581e656b8a6c13efbb07f27f5ff66216c833c8560abb7fcccffaabd42c129be3709aa
#TRUST-RSA-SHA256 18f0f8c0345e5ecb2da7b9a58bc2f49e696deea9e738591b9d1f484417fbabc0ba29d00c8630375977bc5e71a4c68b8c0c8304ad01e78f92dde23c2ba87423eef3d7041019a13c03eaeb5dc64af81d77002f5b5206f79ba196eb8dd423dbee664053e2d4a50a9756ff39d8f88fe354acd9a650ff1c3965670776a5482e0bf1b5895d7d64b866655167ec2aab5afc8ff9f721b06a3b6ebcafc6763b6ad6d970bb4c38ba47da26cbc6d284752b02b56158ae15f45f5a7aa28afef2404831d706e6407773863e4367b7d9fa166043dc766d3a794a16353bef766c4208d2d91778fab6912e88c3459f1c045fce5f62bb0a360d3b833d503111038ad85d568a85befffd3f0acac44384e2fd7577ed90479c92bb123ee6216b99f0428c4ef566f952895041bab27d349ec90afb403e1a91dfc65c6c1b91654428d328b9299ba0e855ab976ad7ed5539e89e5fe75d9cf446a6f89f288fdc5cdc187f6aee1c3fec0b743b32964b13c74e4a62a0c6bec9fd8dbfb8f9e87e1605d9feb1de398891db802b7fa8cf412de4925f858a7e1d9af1729d4d388d4581c7ee08a999753cacc142884bd7d21d61370fd68c7a2b9a8d1a5c04c077be47373b84cb82aedb62a2d39d72075b1deb950b13bceaffa2c927a72d257f9631224ed1fecf23c4c12958b55ffa53b882939f663b9a03cdfcc6da77b513c647d63c6f6da54784fe0a0e21c4d6d8cf
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138359);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-10188");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu66723");
  script_xref(name:"CISCO-SA", value:"cisco-sa-telnetd-EFJrEzPx");
  script_xref(name:"IAVA", value:"2020-A-0296");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Telnet Vulnerability Affecting Cisco Products: June 2020 (cisco-sa-telnetd-EFJrEzPx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a Telnet vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-telnetd-EFJrEzPx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cefd99e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu66723");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu66723");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10188");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(120);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2bE',
  '3.9.2S',
  '3.9.2E',
  '3.9.1aS',
  '3.9.1S',
  '3.9.1E',
  '3.9.0aS',
  '3.9.0S',
  '3.9.0E',
  '3.8.9E',
  '3.8.8E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2S',
  '3.8.2E',
  '3.8.1S',
  '3.8.1E',
  '3.8.10E',
  '3.8.0S',
  '3.8.0E',
  '3.7.8S',
  '3.7.7S',
  '3.7.6S',
  '3.7.5S',
  '3.7.5E',
  '3.7.4aS',
  '3.7.4S',
  '3.7.4E',
  '3.7.3S',
  '3.7.3E',
  '3.7.2tS',
  '3.7.2S',
  '3.7.2E',
  '3.7.1aS',
  '3.7.1S',
  '3.7.1E',
  '3.7.0bS',
  '3.7.0S',
  '3.7.0E',
  '3.6.9aE',
  '3.6.9E',
  '3.6.8E',
  '3.6.7bE',
  '3.6.7aE',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.2aE',
  '3.6.1E',
  '3.6.10E',
  '3.6.0bE',
  '3.6.0aE',
  '3.6.0E',
  '3.5.8SQ',
  '3.5.7SQ',
  '3.5.6SQ',
  '3.5.5SQ',
  '3.5.4SQ',
  '3.5.3SQ',
  '3.5.3E',
  '3.5.2SQ',
  '3.5.2E',
  '3.5.1SQ',
  '3.5.1E',
  '3.5.0SQ',
  '3.5.0E',
  '3.4.8SG',
  '3.4.7SG',
  '3.4.6SG',
  '3.4.5SG',
  '3.4.4SG',
  '3.4.3SG',
  '3.4.2SG',
  '3.4.1SQ',
  '3.4.1SG',
  '3.4.0SQ',
  '3.4.0SG',
  '3.3.5SE',
  '3.3.4SE',
  '3.3.3SE',
  '3.3.2XO',
  '3.3.2SG',
  '3.3.2SE',
  '3.3.1XO',
  '3.3.1SQ',
  '3.3.1SG',
  '3.3.1SE',
  '3.3.0XO',
  '3.3.0SQ',
  '3.3.0SG',
  '3.3.0SE',
  '3.2.9SG',
  '3.2.8SG',
  '3.2.7SG',
  '3.2.6SG',
  '3.2.5SG',
  '3.2.4SG',
  '3.2.3SG',
  '3.2.3SE',
  '3.2.2SG',
  '3.2.2SE',
  '3.2.1SG',
  '3.2.1SE',
  '3.2.11SG',
  '3.2.10SG',
  '3.2.0SG',
  '3.2.0SE',
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2aE',
  '3.11.2S',
  '3.11.2E',
  '3.11.1aE',
  '3.11.1S',
  '3.11.1E',
  '3.11.0S',
  '3.11.0E',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.3E',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1S',
  '3.10.1E',
  '3.10.10S',
  '3.10.0cE',
  '3.10.0S',
  '3.10.0E',
  '17.2.1v',
  '17.2.1t',
  '17.2.1r',
  '17.2.1a',
  '17.2.1',
  '16.9.5f',
  '16.9.5',
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.8',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
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
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.10',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.12.3s',
  '16.12.3a',
  '16.12.3',
  '16.12.2t',
  '16.12.2s',
  '16.12.2a',
  '16.12.2',
  '16.12.1z',
  '16.12.1y',
  '16.12.1x',
  '16.12.1w',
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.3',
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['persistent_telnet']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu66723',
  'cmds'     , make_list("show running-config | include transport type persistent telnet")
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
