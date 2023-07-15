#TRUSTED 044bff50f02ee6fa9bd25f50c4fa92d6c162a9b2fadf2583f82e4a07f61b78b5a37f5f58d7de6bbde1be90732c7e1e3112b8d334620db9f3d705ccba789711b16c7a6d2a49cf496508f9553c6cd7592bed8ac53b7ac64fbbf6d5610c9d31071a85e01c4c578d722cca2299d47fc902cb492fc90d914b47114c7af7ab6998910468eff6cb568563ea8cfaa1f2ac6622b25a132e7bd41afc6e480765a27fb5f4f3090bc67285f17777ef95db786b314fe4c0a9b61df0cdeb64ee2700124c49df00582e9b98497d2e6e4c616fb07306aa4fc7ef9c0df38be2fc181f6a4732be0f24a066e89b3f3d2fad8afcb4fa098086ce49ebb9188fcc5e71616ee0d6a77cdaa293fd7f9584d99ee00ce6f3e3ae557aacdf5d0505df5be44874107379d0df8974594dbb524378e18ac2c424df6f44b6396f9cb3951cbf7049871c7bfab6165c4020d26685467701f74c7b0b4f67eac5deafdeeaad9a3c89db00bd8ac7e13425b05db869d5cf8703c04e6fb47f4d0d59d75ad43b4e5a4d45a2694b27b60388961dcb94996512083d76070b98680cf02962f032e19959409df4a5d4d5192c5f38f6ee584edf07b6f1f95c015223b0872f4fe25187854fe0a4c6f34d6a5e5ae7f07a54a4cbef59d21f6b4a75aa3a85d2d0ff348b3159bf416c75989644a59d255565375c8d78b2e420dd735621a38741a92e1e9c1bcf9fd79e86f733202d0c23ce2e
#TRUST-RSA-SHA256 045db0edfc5cb0cf15a250752c33bfc31433269c4c0b62f4660aee418cd854d382af404ad48e2cc9f630aac036018e919177bed7d8d96ed836779562fb04bd3d7a93361b244c32328a688a50bd2fc8961fdfc3a57c07ca9ae6de616dbb9fd6b809407386461735218c369958e9e7094b86254ab3d51316a59e8716c468f7baf53d094b4fb5e2cd4d5e0c55cced358fc3d3a9bce9463b015bf977f29c775306546a7b36b273390289a5eaf7e5bef3d6c5e553acc7564231c8496f3abd5bde8c66f2e2615195b6f7bfac33c42b9703f0736092201f52dfe1e78e7b31fb1e45fcadf448dcef8ec267f34a86ac7e2dbf5f9f86d5241402320e5d865103f2e68bb760f2a6e39a2f1476079bc4883b20f22892c3688997b7c42728f6aab79ed152a72467ca768a8d2f9ff080a170821a0fb2df0bd30b5408d4501c47bfca05df669e5c13f2b9bbfc2a455f9d064d86ed13bc4a2f356f4f930693b531f743fc00dbd871726568ff7a6349fefc201216500c50d0a7c11bee8be35c500433d6fbeb9b24478ea9d482eeda7176ea7a7c4c19c99b48287d2c5b01f0789044f0c763ceb2ef4788e5ca9b171134a56e6bb55ae95f74b85633c9225bb161a9dd9809fc59a3c198829421e300a1a0d19ccb62f407e940a062a33797793ebec4517c7bbe23f514da1c08ff607a2664fdc19cc759db8c1ad0ec2ff2931df2116d6ad3e151985e1d96
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136615);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3334");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq20910");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr43476");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr49833");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fp2100-arp-dos-kLdCK8ks");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Denial of Service (DoS) (cisco-sa-fp2100-arp-dos-kLdCK8ks)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"A denial of service vulnerability exists in the ARP packet processing component of Cisco Firepower Threat Defence 
  (FTD) software due to insufficient validation of ARP data. An unauthenticated, adjacent attacker can exploit this to 
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

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

if (isnull(product_info['model']) || product_info['model'] !~ "^21[0-9]{2}")
 audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '6.4.0.9'},
  {'min_ver' : '6.5',  'fix_ver' : '6.5.0.5'},
  {'min_ver' : '6.6',  'fix_ver' : '6.6.0'}
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
