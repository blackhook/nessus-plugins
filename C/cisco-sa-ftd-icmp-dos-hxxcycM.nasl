#TRUSTED 71ddd715db16e7e27710a6f92cec16581b7be50c656039749327507b511d9c709f424d5ba1563c46f4627b435e1b8afdbaaac7676b89a8ecdebabe4fce40e6dd558d73a6e80b5b019065657593e224f3ffa92ec6ebcf7de104b7022c7772d67c57adc246c44abef4a2ad7ed3abcc979a2d7f9228467d6c59f245a55b47af49d493bde8355b27c45eedabc00743e0633fcd7d880e0831a3d7fe683eeb0258d5943bee46ff0da24e76e321b3be857b3e1241ed61206b67fbb09bdc98e5c6171af0a942a2ee258f0da4ba684efcf00c0ff51e6de4eafce2d30a645440d606480c264fb4d23d53da23134c7e6fd8b56bf986a390709a332c638663f15ae3e8aedd310480040d79566a46458538212d321f44f5f605a30afaac30c924da7264930148173c26ceeb9a4652fbaeea7a1028b0a14e73188ee618ece9cc73d9eec37eabdca0a2ed6badc6dfeca4b216f6c917136133716e1c25da9e75144c385de89bfbe651620b3d2e5340240be87b31f5f8a7832733e7c9b96dc3de1ae0a49908fd1b708cd6786e87cc123a8e0844bdf941774c3e57ce516709a52c7ca7334e058e597ae80e9ec10ce241c974a4f95477cf5d9626b041fe215647bf859670a26657c99764d22bd0781c4cadb0e776b366641cf86df585f1170b445da44d37b15171c8c3ba7fc8068ef63725c8bd433e29d8cde5bc1549b5ba876a5b8f1e8149d646eab6
#TRUST-RSA-SHA256 27b9189c48ed1965a5024d48486f77007ef73743993a8bdfa1c0ed27101213bb720f4c048fd713363dd5db3168509940779e7ce4c59d11459ecf0c5b23707297a8b5b08bfc0ce6ab694800a02c8503d255f8a0212f0aef13aa423f509b6a2e2261801ba9fa7219838973101cc36ceb1c7abee3f694e5307d7c5a8b008e1ce6878144bb51c1e7f88dfe5ded30e3b1d7adef0f592bba823a14fc37c11d21f8c6c392f4c7ca775928e3b57900e9451906a7013606198f34bdce529e2d72615afee46f7c3bca4d1f2b558bf9cb6dd669ea06563b87b7fe5d7a0a15560938870dc6f6a7fe953e8c2f112535c2b96177280ff6f62e2ac98ba1cbbe8760fad9e39cb69275bc7bbb4b674180fa55900db1af604ef2740f5640b5a41ea93516394ab255ac4c29b78071afda357792d3848997f04b766fd008f458676ae6948b15bc1487a4d02b9671364aeb87872a2494e45858e12ab99bb9169b3e5ba011e48ad0fa1365b75b47c8971b77a8f895fee52fd6aca11d85fe153a59ad34ed71341728f6859a4df9c9dd35dec7f3afc5179c58d99d490829c58bf7a6d04d5b24c5edcacaf228e6c8f35826b0b9645ce787725f0ffb980104a90434ec78fdbc1328f12e769f687a68baead05495ef78c966fc166cbd80f2f4245f7f86824a27ce3edaf19f9b765f291ce5591994e3595f17e6bcd077f2965af9a12df3e8cfd653b91839c12749
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152750);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3571");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt09940");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-icmp-dos-hxxcycM");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower 4110 ICMP Flood Denial of Service Vulnerability Vulnerability (cisco-sa-ftd-icmp-dos-hxxcycM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-ftd-icmp-dos-hxxcycM)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability. Please
see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-icmp-dos-hxxcycM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3e43f71");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt09940");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt09940");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3571");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
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
model = product_info.model;
if (empty_or_null(model))
  model = get_kb_item('installed_sw/Cisco Firepower Threat Defense/Lw$$/Chassis Model Number');

if (model !~ "(FPR|Firepower )41[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.4', 'fix_ver': '6.4.0.10'},
  {'min_ver': '6.5', 'fix_ver': '6.5.0.5'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt09940',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
