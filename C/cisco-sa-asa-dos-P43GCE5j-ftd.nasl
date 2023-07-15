#TRUSTED a9f04c712dbc59cc462836e8bbfadc1e60b96fc8a672de382473595e61c7a74ac0d3f8e44e107d152857b1c231ab869ece79a448382081e6052fbd7ae583fe6f2df647645555f0362178b25754207a8b53b5db0c3b2a829caffea07f97dbe78e0ec897ef9e02d0d0ba111fedfb9f42c3881d55a24bc8bc9be4b0feaaede5f282e8a45bdd9e0ec9c1e2026bb2e815c0f59678bd77230997d33ebec5b8fc34ca13dcc647e248fefbb3cf6623a2927a20a3d2047512af3ea5372f3f07673a38d8f814bf48dda03b958079ffcce59ec169cc2031a8d7dea104c203a75169bf47a346b28787d2fc7f1ee84335b7322bd99458f4255ac6261d30e702ed3cdcf358417e4f4a00a37d0fdffd3f6b882632403947d69d76cfeed376c01ca5eac09da58b556ad313a413dc316987d0e3b11f65f4491d784a3d78fb0d99d6561cb29b2a4d0ff7a44988489316499cf7169b74cb64f16cff66b45a7b28e4593efdd437201d117281927b493a02b59ce44951b7579b3397797d76e6e98217858107f85271518187e8d84f92ea3e55c787035f3855e189b7680e1551ec2f60e8e969c7bdf3156059a9f002668f8107e5c83310be01a48263541f3df69be69827e0e8819d4567b5038ee6711eef763f06730df11d10fcc7b1df25055270f848962d3dfcf14c8b98257d769d0eb81c1211836fc11f9dca02e94a57c2bc86247ceca52856e1d881da
#TRUST-RSA-SHA256 837f9dd62a95665f95316a4e37726871acd2c28b77829c27e28de91da26e8ce741ac6ab472d0c77a852c1334aa091aa6641793649a1ec439853caf67c590bbf9e50fcf8ebf695b853c14f69cdfbda1677c860551b83d94740caebd63130839160a75f948c5e720bd27b76a6ea551779d9ed148d42f82fda42b21677f9f71b24b0a6bb822de9c85a941f8970b15cb1e743b78a1d56a6cfd385494d02d19ef69836bfe7ba6a47b2e03720c848ed16ceec532caa596027bdb1259ecdaff18a58e59c26e926f6f4bf02570a7164d236053387e981fcc06254b3900e4be625a6f20d1ffd0c35d8f3736f49bebbd94b9b9157727359f95364246a7c5677fc6435e4716e330f895198ec9f98b401370d280659a44b6d0c49929d14f0aac63527f2e655c709d8b2cd0b3c5feb4f93d2f56b2c4f3b8b17e769ee708ecb9805389b23b065e0ec92195c9856c82429c4ae4f16189459212275b5210d88706c8d7dd56a29f39670af33a55f0baac8600d1aed86b6cada4d0ac5d8947f4d3e4214b9b909d111c0d69a1594b9776ab0eda98df5078c7567c70713ac53d9cbd32b6d1feb991c46b8a8a97ebad1be9608046cf95c7409b022714d276b39316c79e28fe01a58ba99a4dfeed2d5f7eff00a6b206ec80212ef9426335b29ff1ff5f56d58246d4bf0510a5d6be0f06b93dd2ca0704ca4a14d8bfec68cd39a69d94d12ec553b15d55d566
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136831);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3305");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq66092");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-dos-P43GCE5j");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software (FTD) BGP DoS (cisco-sa-asa-dos-P43GCE5j)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense (FTD) Software is affected by a vulnerability
in the implementation of the Border Gateway Protocol (BGP) module due to incorrect processing of certain BGP packets.
An unauthenticated, remote attacker can exploit this, by sending a crafted BGP packet, in order to cause a denial of
service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-dos-P43GCE5j
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?745a6bc4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq66092");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq66092.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.3.0.5'},
  {'min_ver' : '6.4.0', 'fix_ver' : '6.4.0.6'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq66092',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
