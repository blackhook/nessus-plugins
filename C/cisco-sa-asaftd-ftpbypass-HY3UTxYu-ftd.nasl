#TRUSTED 6eae5ff96beb01168956b7a39a62476b3540eac49eedb0318c3a0de41dc81019a91d735eabc34e5f42c93adff58586cb592dd913da58d6444849f815a7107ba30cfa530aedd3dfdd56abcc0bbf546e8aa7699a9ae88f3fbae4d232e983cd6f088e49a34b7a221ff8d708ad315dc662a954df78723987455f81191462a1ce9a968071e40f51c7cc54b544b1bf6e2a99b0164ab253143a717517023a5999d2119950bd4edeb4f067c2e79cd5b396b45ed4cb7527813ec7e05be8b933f2d3dbb1c9cb89a084c3b9e73884eda32f65cd4cf9c3ef0c76963a33570ab4a29de0d5e3925068646116d8555951a941611ac304b3263b73d1f30f04e3d16eb9b05a65bb0ab54235c64ded51dd5e86458beee947868bf863acb2ec0c6077c6e478ff22d7ab70af7b3fcaa98cb88660cddf0861a0eb5461a8b2bd760ca84789df9de5ab8e45edd5d62bd921dbeae919a9b837fbcb4af6f4b8d0da021dbb7fd413f414291168a122bc4ee6c99e337ebdbdac74683e8af7a960e0932bd1319aa66318c19d09d8d8fb52ac0e1285857c74ce1cbed9e284da5b43e07cfa1cfa5f0ec3af72ee7fb5ef3f86feaf62c524d1e94f131c13a5538c7e2610d0d2e72beadb8f74c1ae2877e149dc4fd7d09f7493d8c27af5b1bde499a8cf083dd85e3e85effc9a8549d4be3d2641f4552f03ed1fea8c8c4800252c3f0fa7e540d0e314d39b7d3779bcbed9
#TRUST-RSA-SHA256 982cec3bacaa3de8129b8a9c624dfb8592ebdc2423046181ce9579480bf272dd92e85fe20e875d628521081ad7730fa9d34487fb2ecb8631901723f7715d731c582d9c41c08294a1db92d839405f960369bc5f3ee1793b84b6fc10dce090eec090abc52890df8eab97ba6bd18f176510fbd3636b0a78dfdd133911f04536110263b3cc5207cd10717b1853921ce70235a7df4ce1b8e383205e3659f78192418e510321d1cbb2ce4cc14564049c8449ef4b49dc53d8e8e0a2c58abd2cfdc8d5d56c8dc6591b46d528bab370551fe10bba452fba0f7422ef11de5bd961227cdc3976ca42897c8cd95fa8b28900861c254253ab24b6dc8cfe7d68cd04d97ae0f1bf2f0fe346700a09033d384d273719664737611c784ff312b961888e656a0df5b0cfd7b73dfe52dac129fcef773eb788399726155c3f945a59d68b12715f2803b9322b3bb774e5a314c65e42e5e1526e3b00c61c79935e11b87d76401cc28e45466122820b9caafe1c205c3eba9b6eaa0f21d46b5116be68f0d8331fd585c0b7756d9b546855718be9f59379e410e92fcfadb7d6c1b973da686f4ee87caf39962d9a04275ac819a487130b2bc8ae193b8366095c091fac36b390d4acba898930820f89c9017a1cc83f76c30e714eed0b8271f8268553fe53e0aa68c79ef2cefa77425654a81f11a4bb74bd6dcdbdf2177d9e24e94a8213c7e7efaa91fec3ab38ff
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164349);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3564");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt13445");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ftpbypass-HY3UTxYu");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense (FTD) Software FTP Inspection Bypass Vulnerability (cisco-sa-asaftd-ftpbypass-HY3UTxYu)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-asaftd-ftpbypass-HY3UTxYu)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, there is a vulnerability in the FTP inspection engine of Cisco 
Firepower Threat Defense (FTD) Software that could allow an unauthenticated, remote attacker to bypass FTP inspection. 
The vulnerability is due to ineffective flow tracking of FTP traffic. An attacker could exploit this vulnerability by 
sending crafted FTP traffic through an affected device. A successful exploit could allow the attacker to bypass FTP 
inspection and successfully complete FTP connections.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ftpbypass-HY3UTxYu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf58e222");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt13445");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt13445");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3564");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.4.0', 'fix_ver': '6.4.0.10'},
  {'min_ver': '6.5.0', 'fix_ver': '6.5.0.5'},
  {'min_ver': '6.6.0', 'fix_ver': '6.6.1'}
];  


var workarounds, extra, cmds, workaround_params;
var is_ftd_cli = get_kb_item('Host/Cisco/Firepower/is_ftd_cli');

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  workarounds = make_list();
  workaround_params = '';
  extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = [
    WORKAROUND_CONFIG['inspect_ftp_strict'],
    {'require_all_generic_workarounds': TRUE}
  ];
  cmds = make_list('show running-config');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt13445'
);

if (!empty_or_null(extra))
  reporting['extra'] = extra;

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);