#TRUSTED 084705c47cf790b33fd85085baa1ab6417a92f770f206f727ae40d8ccb47908a351dd08831406b41fa86f844688debc6b279a038c4b33a2d0f04ac6547359e10dc1edf8305ac2664f2a0c23e43f8c560aa278fd97a56a887c2b42422f0d36e9aaca55d3f639199ecdb2453ead40d4b9338e38ac9966fbeac26f1a5eb0e3c1daa3a402e2f6e744a63661685ac835c052c3082e507285c2e3530f9f818f5789f69398ea53ab5c5582390a5aa068aa5f42bd9896e41a77ea5f8a406c24e91f866ec6fb59c167f06ecdefcff801e36908333f71ca3174bfb7a2b4c765cabb6f7ff03f5aec26ae6b55b883ae83f24bb3ee7c29d71c686ddfa19f0fec69e6ea524c6efd130468f7ba88a6d6526a44278034335de0191895329c53cca98c29f35862dc6c63022ad018d732c604d8c98b885e2e7991363a0c0ff205a91becb810c0c34e15954a682f8fa29cf8c380965431a513de3f160ff8c492e0f43b5520f331a1c226f607d4bdb0ce9043cd054b4ca7ca126bd4f2f79b5e57d0b1662ee90dc59b69fdd2254398555386f111ad0f144fdbeebb321f444e619260674ddd0db946dc168c3cd121d0628d5db6340faf31faf05555016896c4218223ad42c7de5ea87478194fa746b1774dccd399aeef0eda7a4cf144eb21d95f33f5a6fdd7d43d25c3288b5927df26afd4e55aa73a0bd256927958ce56ebf4996afcf6120908d187f0ff1
#TRUST-RSA-SHA256 a53e1246e2f2f27a63aae0718e781b50dcc6ca0fb3631dbf0ff909991b8ef6e35102f10c8fc5797ca2c454a5411959428b753046e04b3a7805f1798b8570bb51be68c40066ff55a0586f1cd6c0d0fa2755b893b3f7abd6c225f59497edd2f1f2b36af8edb76ddbf4b7b419a3f04b53a27899f80782dc80908f5eea509959c684bbb0d341baea9fb52d13292459916220c9169fa958d54b32885969f8d72f8d2c6c576505a9a2b4f12d0c60effa64ecc610ffa146ca9a8cce7dcc20e8321f87ea6d529b2e9e3fd7d2ebb26f6fa2f4aad82a01df3193026c164e3cb02e1dce7dbd584f0a3737c50c6ef04951b4b10a24ebfeb35a10828e99393f8c2ec8510533a3a57d2a1158758d11d6fcb4928e6cf61095ee187b2a891708022a77f1ef0b70a048a63190b886285e90e440656f33820225ed9c27e7c4b817eec7e711c10a8886200c64a5306c0f0b97f47591a5f540a332c1edde46f0a301ca4a093c69318f6eecef0acd24b2982e2de0e3fd05b3b8e63b32dc29a081c3e5a7de2c00321fe78b95b263eede573b15ed1893d876366a13760f9823d6a175c306920633c80cb251f7a1d04e8934619d2d1498d68b36b9924481804717d98a2fbda329155b4defcb1515f43c26bca68570f1e11196319b219e214ee27dd2c42c00fb3c0d96ffc0554155fbf12384d06199999ad1ded4831dc721f1cedd464375da3aafa0960e0282
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152671);
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

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

# Not checking GUI for workaround
if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, 'Cisco Firepower Threat Defense', product_info.version);

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.3.0.6'},
  {'min_ver': '6.4', 'fix_ver': '6.4.0.10'},
  {'min_ver': '6.5', 'fix_ver': '6.5.0.5'},
  {'min_ver': '6.6', 'fix_ver': '6.6.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt83121',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
