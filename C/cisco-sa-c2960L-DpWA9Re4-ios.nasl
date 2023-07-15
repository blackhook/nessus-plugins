#TRUSTED 2f196cae99cabb7dc10cd95da9c84e68b4366b9b2fd65a09beb1c497abf581e9e8723102bc21d6e41c6252c5736e41273bde8fb803887b026e40fa44ab706f0f7520cb8605e36919f8e25063d3353fd4479067163b246657b9519b9d1656e12e6d99a9243f40b3c86c8cec1c94b5f3ac4a679adfcb2b388b63cdd52ec9a0d42cde47fcb4597670b0c72a9302397d9c43c607f0455e52926401ce1c4337ddf944a1b4f983925c1c68d64d92cb9abd5e166f296b10f7fa0a22ed32af6408d5bd6486ab8260c9b6da45f65c52a606d2e4dfcf46f2c83f4975e3b4dbddfeda1a7881def955bed166d4bf4dd524b3e8181e4a2c9685c4cc88d5227a9db3f9ef904257c91fc47f5dcc3d5955229c1246ed2887dcadd722f2dcd34966958fe8064962e3434c77a5ef25208e6064bf6afc17098a36c855e6f7e0d8f4873cbfebfc8feb0af79bc49fe33307b06b424a7b004f352ede795b7370f72450e15a629af7f21f9c1c1188f3ee10d5dff5c38aeeb67eb890278a1d97f33303ee53733e3761f38afd7182a5d787f5240fe7a3958203d8f77e9d30a97537c4ec4f6c706da578d41a9c87265929af6ea4d6d863004635dea2619416087e02adb1620e7b398084d059ef13d9e03e4e232bff9c36a3fc1d5bb4e952dcce9ec23bbc9754aa2f08b3f86a2a15d960c34b7a8e23e0e59331d4a685e59fa68832352ae287989788675cacde6a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137840);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2020-3231");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo57950");
  script_xref(name:"CISCO-SA", value:"cisco-sa-c2960L-DpWA9Re4");
  script_xref(name:"IAVA", value:"2020-A-0275-S");

  script_name(english:"Cisco IOS Software for Catalyst 2960-L Series Switches and Catalyst CDB-8P Switches 802.1X Authentication Bypass Vulnerability (cisco-sa-c2960L-DpWA9Re4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in Cisco IOS Software for Catalyst 2960-L Series Switches and Catalyst
CDB-8P Switches due to broadcast traffic that is received on the 802.1X-enabled port being mishandled. An unauthenticated,
remote attacker can exploit this by sending broadcast traffic on the port before being authenticated. A successful exploit
could allow the attacker to send and receive broadcast traffic on the 802.1X-enabled port before authentication.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c2960L-DpWA9Re4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57a838e0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo57950");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo57950");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3231");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

product_info = cisco::get_product_info(name:'Cisco IOS');

model = product_info['model'];
# adding the hyphen as option since we cannot verify if it will be there in the output
if (tolower(model) !~ '2960-?l|cdb-?8p') audit(AUDIT_HOST_NOT, "Catalyst model 2960-L or CDB-8P");

version_list=make_list(
  '15.3(3)JPJ',
  '15.3(3)JAA1',
  '15.2(7b)E0b',
  '15.2(7a)E0b',
  '15.2(7)E0s',
  '15.2(7)E0b',
  '15.2(7)E0a',
  '15.2(7)E',
  '15.2(6)E4',
  '15.2(6)E3',
  '15.2(6)E2b',
  '15.2(6)E2',
  '15.2(6)E1s',
  '15.2(6)E1a',
  '15.2(6)E1',
  '15.2(6)E0c',
  '15.2(6)E',
  '15.2(5c)E',
  '15.2(5b)E',
  '15.2(5a)E',
  '15.2(5)EX',
  '15.2(5)E2'
);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo57950',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
