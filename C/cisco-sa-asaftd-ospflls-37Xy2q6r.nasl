#TRUSTED 984c6366cadaf8ef42b5e428518e442019025327bc8e3ac08c19dea2fc53607c55671468101d6972a8dd3526cf487e4bc0bf8a5c7f107b0b93ff84f561d4755624995e99179850fa2b8eef3f953c293879b84814b15763b0422000cfb58d167b561241aacf669ae50490800eff5ed3cd4762a03fcc6ad94f129842a9dbcefdd65b62d2905ab233ffc53421eeeaab719502dc4d691c1476129148c0c1c7919ebd70dbe1cd1488e2bd2fd2a1ab2d95711f16116fddce6dc1401d627d501a062e3e74deecbcc44dd2eec16024f04996230111849cb437342b019b955ed1179f266a4b71681f76183addc6fe7cf1064b209b1cc941e58d80ac7326fae7a1b3596fb06ad8c943702c512b5217c1919251f75e63b1c25e97e8963424fa79317254d148e569667349fcf0111f6607d21f3f3a94fb37b88a3fc6146e0487e03283a757ebb381e3419316ff2a41b741e14bcb38624fa8e6b25c6926ad02d2d1daec8752155069dca5e4491aed24cb6126a0d1b9f60e4f2fe4cf412cc62005c2deac6a73be8e72f2aa7ef191834fb4bdd8d6a6b046a80cec901e42b8d3cb136991c56a1ecd5ceb61b07596d3fe23f8303e992a3bc08e67dcac44d8169c8865323b67769d35274323fd03862b7498363d23570f37cf2701ba59b4e322c123aec55fff7f4dd63d526a81ea9febb45bba5a83178e334b1913ec429e1d2654b8c8d47988987eb2
#TRUST-RSA-SHA256 a6382bd782893c9864c302a7212d37745269e1c4ea2a9e2280ab5cb93d41f373fddb4407722046b0e044950774b6e49ce6403e740e456bc3f60717745a20d2169a5ac8a1ca850f5ed0f5d348cc347bfea5c169997aabf223c49b026649eec10fc8bbab1099e6ca208c67bf91050977dedd33270b41fa2a76bbe653aad54e06721be1507a2578a6612c09d85947b81e0c0e7911592cb42637d9f68e9d337a219e069bbb99923e8f59b8acf5e324b6bb6582e8132b02650240b87fde125396bd29dc2260361ac7f0c705bc06eeda46ad48bf1192a79258fba5c9ba0b7f1ca2bc786d8c7e9f882d57ad425054183c82af80e23134ae38698e065d64174a5a5275224d8e7704fc5c42bd519e5cdb5cb5957f4672f374a5f7566d520d24b9139fe0841a2a0247156791d90d8a115e3f5ea702013e8c91d51a4656ac70f0b3361addaed3abc2763c7f5f5896e042cc10df82b06eff8a7ea00c98e6818cf2ed1f5d0dc7aca0f0a5a8e4ca0389303c2ff6074e142b836afa2eaccdae42b61e118349a6022a9ff176d715281cc3b350ba205f950ec54cb51fd2ef870b1daa1bf9b17c9a972ad3cf0c7f4ccb7bd65f42c6384692821c1748a89df5df114f3c2ad6d7222e9c81d051a187aea52db736b4c80c86860990b1c0237c44bdadc212d41d643499bfa46cc81076098256f717835a08c497651b0ed3ad846830dc3e10afe16e7fe9e9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152670);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3528");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt83121");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ospflls-37Xy2q6r");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Adaptive Security Appliance Software OSPFv2 Link-Local Signaling DoS (cisco-sa-asaftd-ospflls-37Xy2q6r)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance Software is affected by a vulnerability in
the OSPF Version 2 (OSPFv2) implementation that allows an unauthenticated, remote attacker to cause an affected device
to reload, resulting in a denial of service (DoS) condition. The vulnerability is due to incomplete input validation
when the affected software processes certain OSPFv2 packets with Link-Local Signaling (LLS) data. An attacker could
exploit this vulnerability by sending a malformed OSPFv2 packet to an affected device. A successful exploit could allow
the attacker to cause an affected device to reload, resulting in a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ospflls-37Xy2q6r
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?896da487");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt83121");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt83121");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3528");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.6.4.45'},
  {'min_ver': '9.7', 'fix_ver': '9.8.4.22'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.80'},
  {'min_ver': '9.10', 'fix_ver': '9.10.1.44'},
  {'min_ver': '9.12', 'fix_ver': '9.12.4.2'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.12'},
  {'min_ver': '9.14', 'fix_ver': '9.14.1.15'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_ospf_neighbor'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt83121',
  'cmds' , make_list('show ospf neighbor')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
