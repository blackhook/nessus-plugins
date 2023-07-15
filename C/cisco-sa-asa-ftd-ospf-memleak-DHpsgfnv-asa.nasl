#TRUSTED 918f3d3443e73af6616015d0aad1b954404f638641dd4f4c8a4c34971e76cde824f9d89f25f3b01a47218cb1895360605a7ab916defb1060bde47d71715c0532fe7e3a8434efccdfbe0ac0cf0cb5badd1414177cddbed8c75f4be07bc082d03e78052bd685d6370128f9f535c86733f2047695957f6c278e11b6d14f2befc279e16cfc2444ce1d95bd52535f56f56758306b112328119cc071f1464a2da1acc04306bc0012dfb12ecdf7329b297a18b50e2a9692e787b567f9c1495d27ca5eee051ec4550d918347f949d23668fb0afb7a749092df5f56aed1fc054e62dbba69491148202637782c4404d43c6d440eadd4ed13155add0653133a9a382cc40b329ddd53e4418ab509e6df167d493b7f60fe5b95016bf44661091edcde50a599df4d689da72af189825450c3492b22f13d5f23607b38588fdd31994f20e25767fac175ce295f5cb69c545ab71b0640a54a8c5fb0c67d6c929c5428e08a411c3495444430e0e7806ea2cc42bc10f19b6291129b370431934efbcb1661035b7540aa4164245ba3812b77aed9652ab0f315647a2934dacfca65933cd47c64fbfc19c9d618b686548e08f57ce374d46e27d87d15a1d062f2c3ea7173d08a3992274f935c1c08999e7f1c5dd60c955c804e762a7c7cce8ce3c58813ea83cf5246dce75a8893d13c973c0a538234bd74d482499b76e233faeecdb0108a1cfd0a28dca760
#TRUST-RSA-SHA256 8837598e344e5a42d37e8455652566c2e29b64f6a253dea34d1e7a2706f5b6ab737f833e0f8de057715f60395680ae6bb08a29aa5566041ac0019e163353cd8c08d3bf63f1927dcc7976e0106b5b56513fb84d3e8ae586ad61fc3c0b20a668f302d8291ab08fc93ed61b8fe649764bfdf65fa1ff54fbdcdb06e8e25738765180dec9247099369793ed786d89da070b0338b6bfe6b9c37bcf48d13bccffb8f9d89fa775d6b5a7af8dd4b8731e7ff3dc8a49e90f06654df97fcdde3b48f51734fecafd1369076d795980724a6d09ce01d35fd57a7d70d66177a5c1d7c1bbde3eb28fa4478c37ae7573fcd5807757885ab9ef92be9d2b9c29c1fc687680feef488e4c0ca92b0182a387a738c75a2e54aa231d0416e138a34cee965aa8df477acef26f3d1e903c128b82a1278ebfa1dcdeca1f2a014380bac045d09ce3deba71d653eca680ba4892ce7ce27eaed483fe79625bf777132c1d2d157561f4580387f5abcf6995ad048df99733ebcba329c1fa4da8261ca48eca4263075a19b2f442c13023c7d78029532cab5ea30e4ef2ebaa928ecf11a27a0df0b1e32680dfbed8515ec69c87c86c809a5bab0b2c3c294fa9d284f14c3a0468ec9b08852aac23a881944755fd504207f63b73eaae3e11fbac0f2079eae13a3aa5e378ab638a4cd808408614ecd615fd859af9ddd789399c53cccd4a395516f8e4e12b33a1f0555864da
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137558);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3195");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr92168");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-ospf-memleak-DHpsgfnv");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Adaptive Security Appliance Software OSPF Packets Processing Memory Leak (cisco-sa-asa-ftd-ospf-memleak-DHpsgfnv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Adaptive Security Appliance (ASA) Software is affected by a vulnerability in
the Open Shortest Path First (OSPF) implementation due to incorrect processing of certain OSPF packets. An
unauthenticated, remote attacker can exploit this, by sending a series of crafted OSPF packets to be processed by an
affected device, in order to cause a memory leak on an affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-ospf-memleak-DHpsgfnv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74b6a456");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr92168");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr92168");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '9.12',  'fix_ver' : '9.12.3.2'},
  {'min_ver' : '9.13',  'fix_ver' : '9.13.1.7'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['asa_ospf'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr92168',
  'cmds'     , make_list('show ospf')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
