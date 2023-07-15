#TRUSTED 5694da781a54a8a41123d8fccbd2e66f253c3211cfe661ea3d1b3fb5269078ab6a9691b7959695ab634cd58dfb585044fd9dab9c115515b2ff7f9fad49f5a94f24c146cbbb4ed47c8b0dd41be10a9135312e249faef935fcd4fd95e77264b6a583420c9a5b30d3ef111c6fdc1733710639fa58b499b5d4edeef08348e9cf20e625344529c89e95092ec685a5fdd405fd17d2c2a82647d74d6b0a758e2f48b4481e3957bac7508a19442df9510169a0a5452c2f33aa5f313ea353e543f6212c21b6d57dae81006afab7ef3dd2bbd9e9126a530118ad4e3d74c31563b2f262002e7d199f3d5bcd49b12fce6738b931fec596dc5ae11aea0deb3e65bf3ba28c0583881d21f1594283780eccbc9082f4e784481158159810a825f2a794ed248e216f20494906cbc2851d4ba053b9312b5f5f7bf6a655cdfdf8a87b65bde39627eff9ed7ae962128476136271be74f59726f384576b83106726b24792ee9c9ececc617159053fb281ce6d286319778047952d25855d6dfa038c5e083db62685c1045d1a36b5330ad7c8c75d86b991b7264b8c15e8a5e76e9ad9a047bdc76eb6a99c132dc22cb760a6cbdf2bc3cdc67f585a5dde80d0eb6c915f2903d6868503efae88bfb60dfdd4471c37c0aee63422d96eb01a4c1953851364064884823abd82ea54614af9f31bbf90fc580ab0d58cbd7eeadb6d411166207b006052d9ffa3ea1a47
#TRUST-RSA-SHA256 4a027f3c00376ccd778bf36c03a2454b19f2241d8e3aa5caab4d41b66c474eff5299ee010cb6011d3843aaf63713b23df60638fdb9fea61a8191680eb9cde421ce758d6c1c0aafdb3dcad2167cd1274d0ad4430087df8b2c49f12b336d972c4527bd21995465b5151a5fbfeb9ee11cd45ae6f149a46733b08be68a476cb0b1e304b36336db79f753d946944088a652edc6ad913559f49c7f217880b0fba043b20524bd4e11c3d2763dc8551a6a77b0f814e458ecf88597226605882c59594f9bdb53814c5de0773d4f61a09eca9b16ed0c9b719078a7afb53e9fabbf79d0307144cdd3f0ecde78c90236a74393d3a44ef61e59631b9715c3f905b0532bd659818eb553b0181fe9c41e93aea375d3e50aa590a2a42b8612e1b7b84e40cd7cea8952f95d0d405c669b1e19e72b1e09370dae2c99e00351290e60e7eb8b07ec703e63ac3b59a449aacc94d3961d490b38901a0295b1cfdff4df096f5a014ba2af77d5dfd6056ba379c2286461eea53b3a5b84e8be3bc5a2901a3a8303bc92ea27a19fc4dda09198ce4ac62d955e8582faf11fbc8fdef28d0be3c31fe91bbb810375cb5c4a5a9be89e62c934c648520e7fdebccd357271c2296609d5b059591032e9124411d33cb888a4c920d45634a4036fb951b4822358627e31354c29ce3691aede447b2c6fb25fd35c578bb673b2927722310572ae29854410c600fe0cebfaa8
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152749);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3514");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu08422");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-container-esc-FmYqFBQV");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software Multi-Instance Container Escape (cisco-sa-ftd-container-esc-FmYqFBQV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability in the
multi-instance feature that allows an authenticated, local attacker to escape the container for their Cisco FTD instance
and execute commands with root privileges in the host namespace. The attacker must have valid credentials on the device.
The vulnerability exists because a configuration file that is used at container startup has insufficient protections. An
attacker could exploit this vulnerability by modifying a specific container configuration file on the underlying file
system. A successful exploit could allow the attacker to execute commands with root privileges within the host
namespace. This could allow the attacker to impact other running Cisco FTD instances or the host Cisco FXOS device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-container-esc-FmYqFBQV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0a81e64");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu08422");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu08422");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3514");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(216);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
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
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var model = product_info.model;
if (empty_or_null(model))
  model = get_kb_item('installed_sw/Cisco Firepower Threat Defense/Lw$$/Chassis Model Number');

if (model !~ '(FPR|Firepower )(41|93)[0-9]{2}')
  audit(AUDIT_HOST_NOT, 'an affected model');

# Not checking FXOS CLI workaround
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.3.0', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.4.0', 'fix_ver': '6.4.0.10'},
  {'min_ver': '6.5.0', 'fix_ver': '6.5.0.5'},
  {'min_ver': '6.6.0', 'fix_ver': '6.6.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu08422'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
