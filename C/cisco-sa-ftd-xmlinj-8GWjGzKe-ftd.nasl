#TRUSTED 141e9a5789b5777f27b0240ab47bc534b8fd1a1d8ea68cf86f247127061cf56784a1c84ec51273e8673f92bfaee67cc3e7e7bba08b01603ed8acaa280543efca4cdd9cc94da9391281e2f5750450212e2c8d8c1da426b087145a840fc9dc46d6aec7d7daeb1afc553a3a442ed2b64a53138f699e81a8c804d3998cffa170447ef8421c0c02264bdb857114fe43293aba86d418732323b8b66395399eda64c4850a4822b0ab51946df083cff1c4ebee2db7d9dfdb31e6ea450fa254ffd69d1f9c71f13411610f1646af24ed0c2bd1e8afe1c4d2b30d7479872785c9b4c1e509c7a4b6d4a7c64cfc2707bcd34beb4252f73528abc3d3a7a38a87f053c9dd156555dac1b009ab65e90569a840c7a443ea73d6169bf81c3b0ab55e7197d217d735de7100384f93fe78889217ca15e66e5731c8ecf6c4f7208d4bc99f416967191da476244d196014999b1a607df4f9d7b2785a9634637d63a2bb560a7dedba7daca3f3b686cea5b44343b36a4b8149225b243dc1910299e48abaa1ea0f84ae3671f4d6b6beb603e8a5418e97a09ca2ddb143312e7183bce9f107b7a72e6dd6e606d6a6807bd3daabe6257b77039058021bf8ee793a98bf8c3d58c6d4a66bc579a9ed26d04534063a4f014b171fbef96b105b05b00104c1737c490b375fa717ae72d8359de2d5c7985e0f6fe81ba432459b548942ddd5fbed72a36a801387422527d0
#TRUST-RSA-SHA256 7e96a84b11bab2defbd8097602f0524cdd6b1e3cb2fa64fa1c1b1e55d034511f5a106df9bfda305a0f38585029ceff641491723df135be23321ea189d4bcb1ee38bd2fdb168277c9e7f90d926d901938fe707ed30feabf2232ecccd9f966baceb72e0b95c88b2d509b49408cdfdb3eacf78581cf298c3fd364cdda2fbb6fdfa9618accad0642a3c338c0c55afc09e47938b2f70704debc6cee87ee733aefcdeaa357d0271808998e6c578d5e480d168b116d7ca8587dbdcbd533c5934b9f72713b7c3a711158e612761380f6f8aba5d62fbf03a1a81afee79e4a30854a61d2f574c4375fa4a7a290acb373c6c37524ffaaf9e5f0432a6bcbc5054b87761428c4076d50262d0a8fda18b1bd23826656dee2cfe7a66a4659dd51864855a7a4da8fdcb1d234c2ae8458c185323a464dc0c72494cb6ccae954dc6b69464980209cbfe13e6f5b768de1a55c3bc4fd3e93349c414551b43148c2058336502828a92d407aa4e60b2a50691d7c6adab0936e32a1562d129ecf230bbded42c58cb0cec8e32a36411dc1c417492b3e24183a446faba3d7d8a9c15ff7e1cb95e4ae8f5af114c13d2dd952c5de0a020bbad970fc86d9b83804dffaa79664ca448a01c6fd73d3d8e8251df3ca12be249b67123cb4bb92d7145dd45b1751aecefc20a90886a9469cbc5cfdad4c825b7af97c05aaa01396eea9dc22ec55bc3ce6693ad4f37012c3
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160535);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2022-20729");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy41763");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-xmlinj-8GWjGzKe");
  script_xref(name:"IAVA", value:"2022-A-0184-S");

  script_name(english:"Cisco Firepower Threat Defense Software XML Injection (cisco-sa-ftd-xmlinj-8GWjGzKe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by an XML injection vulnerability.
An authenticated, local attacker can inject XML into the command parser, which could result in the unexpected
processing of the command and unexpected output.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-xmlinj-8GWjGzKe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1144d4ef");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy41763");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy41763");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(91);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.2.3'},
  {'min_ver': '6.3.0', 'fix_ver': '6.4.0.15'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.2'},
  {'min_ver': '6.7.0', 'fix_ver': '7.0.2'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvy41763',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
