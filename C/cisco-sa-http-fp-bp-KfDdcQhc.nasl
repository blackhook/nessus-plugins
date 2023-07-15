#TRUSTED 7fdc173a2d3561d15601070cd33df08a517cea01be473a2744670c3916ae0c47f9364a56bb8bdbf2737166a482e714b8ba0266a1f5b51eadc10fb593abc9fefbbee238806b0d8b7e6462d002033473874a19d042796704cd2521405cd4c0837714a3eab9e091d9e9fcf8eaae7c91cb884d4efa7f8023a5df8803f09ffc850caf1bba18d2b60b10af817862225fbcbd277fe49a0324463756e1ce210d5c714464bf9bfaf08565d59e60dfb44ef93227287dbb284bffb9c484358ad065c129b835e42f6c9e65c7a7d26b18679f196867db2d174b56ed5346888501fc8a2629d349d659461f659d696e3406e1f72b30b69dbbc371c764abc66499cdfd7d2d5babf2622957915dd432a849dcd73dd194fb4b3095c8cceb06ba673fb8519f7b26573c1248a452326440383e67c6fdfd8703584c0314a99010d4962a84d74fed55c9b63a83028deb593602243fa086dce8f4d89253b2cf423e9c67363a55ce8b4f7ab02ce9de1a6daa04eda8a7741b7410ac4a1ebbb4feeef31195f3c4a30a79202bba6e70b0ef20d8626eb8180350d7853d3bd7746a61c9b9b6c8a2c2935e952ea2fb73842e5251402ae8cd7551fe1e79bf5ddb39b169c10943548e565ca33fca2c06ac1473e6dc468e81cb4a6db50693d5189077284472d2956b90c95ebde40465ead7001eee26011187d727ac149f2680262bcb4931e0ad33a0e010bb7aafb45dfd
#TRUST-RSA-SHA256 23d95dce15ba362ef3bf70721ea39aa86528629e6bb8434cb490f4dbc2796f7f44b617491b2a0316a064a27f63f843ee962f387b5d402cac12ac551b519124b00ff2c2a87d051137ea3294a7c106bdeb019c79c7ab743ee6050ea829818524c42ce2cbd999f3c3eb124c693db374d626b5a831baf74f1e690516e09816a8753e71319f5bb34801770c024ff83e8ab1218de3a2da54d0b2c231da62a2e6e8ae5155ba352316cf3fece8179f6f13d57453ad7bc2659a488fc8e851258f39d5e06cb301b1daf24906b677a8c54205e3be194fa01f7c47cf594d1d61895617cbbad6674b7ff00ad583ad979b7540cfbf92008f65b2d4e72e022c63f5ca1f32ed2931921f25ba0033661125256cc878042e1ff8c4213745c3c0f99707098effe908bfa4d07bc43c1d7558beecb38841cc99506cd364d6ed4d7d6f08a300c72a8214c20b1770c501aeec3e2de36a44892c6df10899075f98898d2185c84a1499b646728b869900c4f2ef63fee0a047a8ea09ac22265a83c91a76e771cd1d26555711b6bbefac3ca12c18167b97382f0340671f036dec6a5cd64dd4a25aeceb3a93b2264ab6d14c70b9f875c0cd6eb2cd2b23d048d29935c1fb0778b06a4cceb5755dbf54c7b98d3dfca203ea7e2ea1e79979bb9df7473d76ec0d17372d758d85e99aca881048c47b4c113f62f7849ca7b4100dab29c4056549a1d4cd17cd41dce90fe9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150058);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/28");

  script_cve_id("CVE-2021-1494", "CVE-2021-1495");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv70864");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw19272");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw26645");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw59055");
  script_xref(name:"IAVA", value:"2021-A-0249");
  script_xref(name:"CISCO-SA", value:"cisco-sa-http-fp-bp-KfDdcQhc");

  script_name(english:"Multiple Cisco Products Snort HTTP Detection Engine File Policy Bypass (cisco-sa-http-fp-bp-KfDdcQhc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a vulnerability in the Snort 
  detection engine due to a flaw in the handling of HTTP header parameters. An unauthenticated, remote attacker can 
  exploit this by sending crafted HTTP packets through an affected device. A successful exploit could allow the attacker 
  to bypass a configured file policy for HTTP packets and deliver a malicious payload.

  Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-http-fp-bp-KfDdcQhc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d5152c8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv70864");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw19272");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw26645");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw59055");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1495");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(668, 693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info, vuln_ranges, reporting, model, pattern;

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Affects Multiple Cisco Devices
model = toupper(product_info['model']);
# everything is checked via uppercase
pattern = "ISR[14][0-9]{3}|ISA[0-9]{3}|CATALYST 8[0-9]{2}V|CSR82[0-9]{2}|CATALYST 8[23][0-9]{2}|CATALYST 85[0-9]{2}[-]?L|CS1[0-9]{3}|C8[023][0-9]{2}";
if(!pgrep(pattern:pattern, string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0.0',  'fix_ver': '16.12.5'},
  {'min_ver' : '17.1.0',  'fix_ver': '17.3.3'},
  {'min_ver' : '17.4.0',  'fix_ver': '17.4.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_summary_snort'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv70864, CSCvw19272, CSCvw26645, CSCvw59055',
  'cmds'     , make_list('show summary')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds  : workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
