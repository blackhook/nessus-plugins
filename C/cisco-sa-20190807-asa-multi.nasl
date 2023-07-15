#TRUSTED 6539e1ce50dd31f34e1b0332160ad917ee9e71a4404359c62fa8d8c5509eb17f71a89dc2b820c9baa14810d4f518cd4a99cec46df84629efa644d19de6b4654898dc9d8419b43ec41f4ae2434c1b5375dfcd80e6541b2c13b5b518d903a0b5b76df57090cb225ed74fd21ed7b71a9d77d6b67a6716d6e8c1ace4c50f359998793bff919ac0f634c0ce1a56af4141d061491d8be6a2b8b5d559a64cd3c414b4325b5ff4495e1575fa5ce2fe3395dab24ced128c04c089c00b22b66362fe9a3694958c86bed455cd6fc01c7d14a6b7c31e4db2118a64dbc5f3ab6d6ff8c07306eb734f82684e5d87cdbcc8baa9d9afdaa94a821b731b772e25f6546d6396288379aac03eeb137cc4b24d035d06d4ad8db9c97e2ebb32d16ac5c0ba17c34e13d0b0fb7d4dcfd6c55635f3963f4646e6ea389b481608cc4c258e2bf447545344b42294f242eb819417fb263e8cbcf2e9101349180135211f1c75eac38983599fd495313917411e47e7f4f42e28cea401f10a463490733a691b36b78017ba222c49f1afae7a127341e86c6fe40e80bf5acb99b5b1450c13ba52d314eb9baf756b70f7d2c8c3ccf47cb64b9f9b245b7958c4f28cf2e76cce5f84466f20decb70d0de91c137e6e4487e89dbdb0f515cad30567f220922eedadc6ca199fa1329b08fad45080d511b01302b827a75a056f475f8aaf68d68efc89cb5c1de507d37e262da2b
#TRUST-RSA-SHA256 7aac258113d930905ff9bd0ac844d880e9cd9f920a1438da3b135a47f06dcd25d430cf8a0197dd8143abe1b3782a12bad5a91e9f8cc14fd51585ce834d5ead2d0d2d4ee0d02d54ef9125d11d5852b08cb197b22ba3ce79a1cc88373ad6d76c62ee9bfd9b9bd5beb4fefd6f6edf12b34883be412ba35cf31988721d51e5c0bd4e7f2e3357c989fb666a2fc77313f92f1310f0f258c25f18c0d1f3d5eba1259b82fa31aec75a8b164e47bb1c03d9964ca1aeca44463906f1c57bde012b0af7b50caca3c5ec3c8b3ffb72b3099cfbc022d7d86e795eead0db4e5e9a7f4c8296aa8025f2e286566374595c0bf3fa03483db6356994eecc76584a17fd9c72b1b40ea934626a8c8194788a15d4b29c27e7fce04b43e9ac2b56304c79048c29f9fcbbf3ec186a892afe227b8dfc524e2cdc4c93acf7d96e2eeb427cf9a7656515194c20b793751cf0d9837ef06b49d35673e1417f7f6ed71b33d71daf5d556ef14ad078e9ee3aee2dabc6104b5c91d8b1b32c5a79dda646905473fea48fbfe1f06c394d53c50eafc9777f495de384f772800c78df4f98bb0b08017ca2463a74c7682b0bd1537ec8527a038219a8072c07fc76d10084a4428e42e66844c56676c3a3e05445b52c0b64b8a0ebb2dfe1be8220db51cb95d190ab6fde5541871b79e8d127f0031ce888795de0c11360f002ceb92cfa2db910fec617e7489949cf88f4ef8d14
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128081);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2019-1944", "CVE-2019-1945");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo78789");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190807-asa-multi");
  script_xref(name:"IAVA", value:"2019-A-0305-S");

  script_name(english:"Cisco Adaptive Security Appliance Smart Tunnel Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance (ASA) Software is affected by multiple
vulnerabilities in the smart tunnel functionality of Cisco Adaptive Security Appliance (ASA) could allow an
authenticated, local attacker to elevate privileges to the root user or load a malicious library file while the tunnel
is being established. For more information about these vulnerabilities.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190807-asa-multi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f51e243f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo78789");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo78789");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1945");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.4.4.37'},
  {'min_ver' : '9.5',  'fix_ver' : '9.6.4.30'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.7'},
  {'min_ver' : '9.9',  'fix_ver' : '9.10.1.22'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.2.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo78789'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
