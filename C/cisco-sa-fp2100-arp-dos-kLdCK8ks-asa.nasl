#TRUSTED a509baa9ae39f32af000078c83ae1e6f4d7a2cbaf6f95e15f61f1915fc29f60e72365a0aa2f8563f1b8a9ba68bac00ebcf497388ca35cd7ce70f359fa89a38955893ed74e7d40b463ae447a9dfd8bac73f75062de9a26e4ef7aecf6b2029c96f7c2400dec6ff1cf59088d9736f5f2fefdad5ecc7431351afdb751a937d2431ba8cd970d2cdf62a7a9644957a882de2a346db07dbc519e0c4d2209f98b99016041189d9edbbe486dbb54d819ec5034e3e6f92b127d7b4505268b9613066b924689a52a9a2007be4833ae8de955f5e78f801edbf74bf9510e3a4e97ed7216b853417a14632841f5a722533f95a7b59778707592da81627c8bca73bcb3ce2fb9983d0cea1bc2ed4e4e43309a7f564dd018decd7a3a76b9427c1d8e0169432cd6147e32aab0a6a58dcb111a767d8211177446b9ad75de7dc23eb378774d01bfac2e9b3ff9d50e37f492a4efbd27a55e61ec15e89f1ee6754c65f630349c7716ed411cabad7014ea339a187d73f1c3a9a387209f18344942b02e4f13e1ec18d403234307f4ab5e2c3f91ac1cacc2664d35a1fb41cb64a26e7b60e5959e84b7d94a9498937b490d9240e76ed8b5faafd762c90e379228ffdd3c51f30edac4ec4c15309e173616eb8dc0be6732063de68048cd086558c65e7eaf15877ebe89f85b5d613b9e7f959bf46d0fda6136a2c183d6018524b9f79f1dd610053d12349d09e4426
#TRUST-RSA-SHA256 02b0bda08ca8612192ebf749f220e0e2b05109badbd59b319c3782022c254d63eb86c0737f823e3aada3990b5c16f5e3c6f907f75e20b3e5b8bcd52c343e82aff0785c1372fb7272d8242122b5fc24b22211d0dcb4264635ff8d961424e77afe30257b097820d4ffdb569e69f7a7766ab23ae840bd04cfae2e49e2ffb06e26fb026651b1491cd0e3fd283bcf7eec6b0507a07653627dd40067166b44f0a49cd4c84a007b8206efc9ff7413d37dab061a49d72031fc2c9cd95265167ba911273149bb226c80137964cc151e81d82b32c4c6aae25a0825d86b90b150269088864c92adc997a07b005aa43f461a07706bd93d3ced5950b7c77ba6c9ce8721adc5e7856c314ddeb19ce397aff99e13844a31901448f7c2a5cc8daaeb7246ccebd8936f5a7c7e688f85781da9afc6235baec96917eb84c67d76cf56025f257e1ed2325b25fd00ee9836c4965ccd5423e57051ac2dca63f71589e41c9a3cd76993dfb3407540c2867ddeb99fa96e0b38ba46459ba3c1e862e8c05332eb4882853738e3d19915f0880e8488e7526e09ee8898f7341c214f51942c967599bfc2ace17fa6ebfbd2b65f01568195f2092750eb9ad9031c3fdd867a25f21a32a04252e761e93635f4586e3f0156b4ac8059828a7e89aa7036ae32c7f5ab03956926f83939eb928c7b0f95d48160e4a8a764f44e16a98d93a45454b81f68c027079a9b04c16f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136614);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3334");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq20910");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr43476");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr49833");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fp2100-arp-dos-kLdCK8ks");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Adaptive Security Appliance Denial of Service (cisco-sa-fp2100-arp-dos-kLdCK8ks)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"A denial of service vulnerability exists in the ARP packet processing component of Cisco Adaptive Security Appliance 
(ASA) software due to insufficient validation of ARP data. An unauthenticated, adjacent attacker can exploit this to 
cause to cause the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fp2100-arp-dos-kLdCK8ks
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfbfdb5b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq20910");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr43476");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr49833");
  script_set_attribute(attribute:"solution", value:
"Update to a fixed version based on your hardware. Please refer to Cisco bug IDs CSCvq20910, CSCvr43476 & CSCvr49833.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3334");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

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

if (isnull(product_info['model']) || product_info['model'] !~ "^21[0-9]{2}")
 audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.10.1.37'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.3'},
  {'min_ver' : '9.13',  'fix_ver' : '9.13.1.2'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq20910, CSCvr43476, CSCvr49833',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
