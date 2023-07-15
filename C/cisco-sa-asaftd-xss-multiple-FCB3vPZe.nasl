#TRUSTED 754d9788ff86a47786d07ca7ab19e8c0b26bb820614562dcc7d2a6e68f5f95cf11d11cab87b4cb87d63a3f055e2e7149bbeece550931e383ca618fda6ed0b5fd9ec4bef8934a16082ede049285284f227b62c66b2cd43f5f556e001390dac1cda420be632cc60fae35a5682fb0d538fd8dd422e319459fe72c1cedfde26f6b25a0fda345196aba3f7bdcda8e0e56121142496870a19504cd0a769f358db1a490e69b9e9eaa9004017f455014a4b142528e0b4d208a0298b1aad54db82b36d2839e06153b567ca709106f38d3f521071d0f03faf14a4a551989791546af8dc78a2848aae2574c9833e093f02a02e1b372b6c0e5aea10afcd452657881e8c2e2581f017151dfbb136f5eca6d82007f6af0970277fddb32cdf05387c83e45eaef65d529a654e7305b1c0b6e7f88d6970c3d182c41aaa64bea078559b17c1df3426c9183545ae7e6b873da8b7070b331ccf64aa3205ab64295c34e5be0b1ff5be69cb58419dba37d238acf6ab89959e704571bd5f8816a2f4c59158b9e4593e3a86822d47aaa32c3e90ea7327f0b485141b963821649a7aa0f23e0cae1288879bd399c3e3f9980a07d15e9c20dd7f345294404482a6941a8be72461e49d3dbcb709d6b085c7c7d3ac808692f3903e7eb993c13f91aabee3ca861f67d2f6f93c5767f5dce944874a97bf8756aa0a1e296c99cb4bab3c7ac9287b583916cfc31f0debe
#TRUST-RSA-SHA256 43587fe49d6cfac1846e37caac6ee209fa744916182b5d2ea1aa3ab1374d510a9b75365c5e149dd763f4cd7abdbba61ef9c20f2b5fd79ca1eb8826fd32820f0de0a7105da0d36f6c93ef091666ce96640d8218b28b4aba2f174dbb2d2bf89d22e8f3cde1a3adb3038ac34eb9e982a340970df0b76f4914ee2086d11b52fab631bf22cbe224a1a2049764b2090c67e461576b8e9bcfe84b9a6e7dc5d827b75c9b532a0da993b1e400c956edb88d95092caa275b775fb840cc820b27de682d4f279ac514db3181ec3e30ed83c40768d188ef546c0460c2bafba747499d3e68a9829e2315ba20d00665231e8e1f432fb8526bc6340037964c7c4f922dbe295ff79c3d92e706a61671e55eac6f065987222f41d2c992899ac22b4a7584714d3f7b7101961803903b36094fd68f59344e325f6da0218479c963ac63fdcf66dc7e96316b23092faa25e4ac07ade75123dd733320d0679ec73bf9ea6fb75fd55772301af7049c86f9282710c9739c7c54293c9567859a327287a8b70ea9562988fd3e178107c3f09839e0557f20b4ee30a9c9c87a6ae25b10923864b4180fc3c60c51cf148ddf0605ebbb4af40c87847ac438eabd86e4f6c89bff9af20d893060a7887a5086ff2269530ccc19ae43ae1bcab5e2e60334ace1137fb80345dfb28707f9cacb0631ae3756a24718b0b30eafcb1cdf63792647a043d0802fd00855b286bd36
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150997);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-3580",
    "CVE-2020-3581",
    "CVE-2020-3582",
    "CVE-2020-3583"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu44910");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu75581");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu83309");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv13835");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53796");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-xss-multiple-FCB3vPZe");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0031");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services Interface Multiple Vulnerabilities (cisco-sa-asaftd-xss-multiple-FCB3vPZe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-asaftd-xss-multiple-FCB3vPZe)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by multiple vulnerabilities.
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-xss-multiple-FCB3vPZe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f256d96");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu44910");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu75581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu83309");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv13835");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53796");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu44910, CSCvu75581, CSCvu83309, CSCvv13835, CSCvw53796");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3583");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info, version_list, reporting, workarounds;

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0.0',  'fix_ver': '6.4.0.12'},
  {'min_ver' : '6.5.0',  'fix_ver': '6.6.4'},
  {'min_ver' : '6.7.0',  'fix_ver': '6.7.0.2'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu44910, CSCvu75581, CSCvu83309, CSCvv13835, CSCvw53796',
  'xss'      , TRUE 
);

workarounds = make_list(CISCO_WORKAROUNDS['IKEv2_enabled'],CISCO_WORKAROUNDS['ssl_vpn'] );

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  vuln_ranges:vuln_ranges
);
